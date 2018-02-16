/**
 * Copyright 2016-2017 The Reaktivity Project
 *
 * The Reaktivity Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package org.reaktivity.nukleus.tls.internal.stream;

import static java.lang.String.format;
import static java.nio.ByteBuffer.allocateDirect;
import static java.util.Arrays.asList;
import static java.util.Objects.requireNonNull;
import static org.agrona.BitUtil.isPowerOfTwo;
import static org.agrona.LangUtil.rethrowUnchecked;
import static org.reaktivity.nukleus.tls.internal.FrameFlags.EMPTY;
import static org.reaktivity.nukleus.tls.internal.FrameFlags.RST;
import static org.reaktivity.nukleus.tls.internal.FrameFlags.isFin;
import static org.reaktivity.nukleus.tls.internal.FrameFlags.isReset;
import static org.reaktivity.nukleus.tls.internal.TlsConfiguration.TRANSFER_CAPACITY;

import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.LongConsumer;
import java.util.function.LongSupplier;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;

import org.agrona.DirectBuffer;
import org.agrona.MutableDirectBuffer;
import org.agrona.collections.IntArrayList;
import org.agrona.collections.Long2ObjectHashMap;
import org.agrona.collections.LongArrayList;
import org.agrona.concurrent.UnsafeBuffer;
import org.reaktivity.nukleus.buffer.DirectBufferBuilder;
import org.reaktivity.nukleus.buffer.MemoryManager;
import org.reaktivity.nukleus.function.MessageConsumer;
import org.reaktivity.nukleus.function.MessagePredicate;
import org.reaktivity.nukleus.route.RouteManager;
import org.reaktivity.nukleus.stream.StreamFactory;
import org.reaktivity.nukleus.tls.internal.FrameFlags;
import org.reaktivity.nukleus.tls.internal.TlsConfiguration;
import org.reaktivity.nukleus.tls.internal.types.Flyweight;
import org.reaktivity.nukleus.tls.internal.types.ListFW;
import org.reaktivity.nukleus.tls.internal.types.OctetsFW;
import org.reaktivity.nukleus.tls.internal.types.ListFW.Builder;
import org.reaktivity.nukleus.tls.internal.types.control.RouteFW;
import org.reaktivity.nukleus.tls.internal.types.control.TlsRouteExFW;
import org.reaktivity.nukleus.tls.internal.types.stream.AckFW;
import org.reaktivity.nukleus.tls.internal.types.stream.BeginFW;
import org.reaktivity.nukleus.tls.internal.types.stream.RegionFW;
import org.reaktivity.nukleus.tls.internal.types.stream.TlsBeginExFW;
import org.reaktivity.nukleus.tls.internal.types.stream.TransferFW;
import org.reaktivity.nukleus.tls.internal.util.function.ObjectLongBiFunction;
import org.reaktivity.reaktor.internal.buffer.DefaultDirectBufferBuilder;

public final class ClientStreamFactory implements StreamFactory
{
    private static final ListFW<RegionFW> EMPTY_REGION_RO;
    private static final ByteBuffer EMPTY_BYTE_BUFFER = ByteBuffer.allocate(0);
    private static final int MAXIMUM_PAYLOAD_LENGTH = (1 << Short.SIZE) - 1;
    private static final Consumer<SSLEngineResult> HANDSHAKE_NOOP = (r) -> {};

    static
    {
        ListFW.Builder<RegionFW.Builder, RegionFW> regionsRW = new Builder<RegionFW.Builder, RegionFW>(
                new RegionFW.Builder(),
                new RegionFW());
        EMPTY_REGION_RO = regionsRW.wrap(new UnsafeBuffer(new byte[100]), 0, 100).build();
    }

    private final RouteFW routeRO = new RouteFW();
    private final TlsRouteExFW tlsRouteExRO = new TlsRouteExFW();

    private final BeginFW beginRO = new BeginFW();
    private final TransferFW transferRO = new TransferFW();
    private final AckFW ackRO = new AckFW();
    private final ListFW<RegionFW> regionsRO = new ListFW<RegionFW>(new RegionFW());
    private final DirectBufferBuilder directBufferBuilderRO = new DefaultDirectBufferBuilder();

    private final BeginFW.Builder beginRW = new BeginFW.Builder();
    private final TransferFW.Builder transferRW = new TransferFW.Builder();
    private final AckFW.Builder ackRW = new AckFW.Builder();

    private final DirectBuffer view = new UnsafeBuffer(new byte[0]);
    private final MutableDirectBuffer directBufferRW = new UnsafeBuffer(new byte[0]);

    private final TlsBeginExFW tlsBeginExRO = new TlsBeginExFW();
    private final TlsBeginExFW.Builder tlsBeginExRW = new TlsBeginExFW.Builder();

    private final OctetsFW octetsRO = new OctetsFW();

    private final SSLContext context;
    private final RouteManager router;
    private final MutableDirectBuffer writeBuffer;
    private final LongSupplier supplyStreamId;
    private final LongSupplier supplyCorrelationId;
    private final MemoryManager memoryManager;

    private final Long2ObjectHashMap<ClientHandshake> correlations;
    private final ByteBuffer inAppByteBuffer;
    private final ByteBuffer outAppByteBuffer;
    private final ByteBuffer outNetByteBuffer;
    private final ByteBuffer inNetByteBuffer;

    public final int transferCapacity;

    private final Function<RouteFW, LongSupplier> supplyWriteFrameCounter;
    private final Function<RouteFW, LongSupplier> supplyReadFrameCounter;
    private final Function<RouteFW, LongConsumer> supplyWriteBytesAccumulator;
    private final Function<RouteFW, LongConsumer> supplyReadBytesAccumulator;

    public ClientStreamFactory(
        TlsConfiguration config,
        SSLContext context,
        RouteManager router,
        MutableDirectBuffer writeBuffer,
        MemoryManager memoryManager,
        LongSupplier supplyStreamId,
        LongSupplier supplyCorrelationId,
        Long2ObjectHashMap<ClientHandshake> correlations,
        Function<RouteFW, LongSupplier> supplyReadFrameCounter,
        Function<RouteFW, LongConsumer> supplyReadBytesAccumulator,
        Function<RouteFW, LongSupplier> supplyWriteFrameCounter,
        Function<RouteFW, LongConsumer> supplyWriteBytesAccumulator)
    {
        this.context = requireNonNull(context);
        this.router = requireNonNull(router);
        this.writeBuffer = requireNonNull(writeBuffer);
        this.memoryManager = requireNonNull(memoryManager);
        this.supplyStreamId = requireNonNull(supplyStreamId);
        this.supplyCorrelationId = requireNonNull(supplyCorrelationId);
        this.correlations = requireNonNull(correlations);

        this.transferCapacity = config.transferCapacity();
        if (!isPowerOfTwo(transferCapacity))
        {
            throw new IllegalArgumentException(format("%s is not a power of 2", TRANSFER_CAPACITY));
        }

        this.inAppByteBuffer = allocateDirect(transferCapacity);
        this.outAppByteBuffer = allocateDirect(transferCapacity);
        this.outNetByteBuffer = allocateDirect(transferCapacity);
        this.inNetByteBuffer = allocateDirect(transferCapacity);

        this.supplyWriteFrameCounter = supplyWriteFrameCounter;
        this.supplyReadFrameCounter = supplyReadFrameCounter;
        this.supplyWriteBytesAccumulator = supplyWriteBytesAccumulator;
        this.supplyReadBytesAccumulator = supplyReadBytesAccumulator;
    }

    @Override
    public MessageConsumer newStream(
        int msgTypeId,
        DirectBuffer buffer,
        int index,
        int length,
        MessageConsumer throttle)
    {
        final BeginFW begin = beginRO.wrap(buffer, index, index + length);
        final long sourceRef = begin.sourceRef();

        MessageConsumer newStream = null;

        if (sourceRef == 0L)
        {
            newStream = newConnectReplyStream(begin, throttle);
        }
        else
        {
            newStream = newAcceptStream(begin, throttle);
        }

        return newStream;
    }

    private MessageConsumer newAcceptStream(
        final BeginFW begin,
        final MessageConsumer applicationThrottle)
    {
        final long applicationRef = begin.sourceRef();
        final String applicationName = begin.source().asString();
        final long authorization = begin.authorization();
        final OctetsFW extension = begin.extension();
        final TlsBeginExFW tlsBeginEx = extension.get(tlsBeginExRO::wrap);
        final boolean defaultRoute;

        final MessagePredicate defaultRouteFilter = (t, b, o, l) ->
        {
            final RouteFW route = routeRO.wrap(b, o, l);
            final TlsRouteExFW routeEx = route.extension().get(tlsRouteExRO::wrap);
            final String hostname = routeEx.hostname().asString();
            final String applicationProtocol = routeEx.applicationProtocol().asString();
            final String tlsHostname = tlsBeginEx.hostname().asString();

            return applicationRef == route.sourceRef() &&
                    applicationName.equals(route.source().asString()) &&
                    (tlsHostname == null || Objects.equals(tlsHostname, hostname)) &&
                    applicationProtocol == null;
        };

        final MessagePredicate filter = (t, b, o, l) ->
        {
            final RouteFW route = routeRO.wrap(b, o, l);
            final TlsRouteExFW routeEx = route.extension().get(tlsRouteExRO::wrap);
            final String hostname = routeEx.hostname().asString();
            final String applicationProtocol = routeEx.applicationProtocol().asString();
            final String tlsHostname = tlsBeginEx.hostname().asString();
            final String tlsApplicationProtocol = tlsBeginEx.applicationProtocol().asString();

            return applicationRef == route.sourceRef() &&
                    applicationName.equals(route.source().asString()) &&
                    (tlsHostname == null || Objects.equals(tlsHostname, hostname)) &&
                    (applicationProtocol == null || Objects.equals(tlsApplicationProtocol, applicationProtocol));
        };

        defaultRoute = router.resolve(authorization, defaultRouteFilter, this::wrapRoute) != null;
        final RouteFW route = router.resolve(authorization, filter, this::wrapRoute);

        MessageConsumer newStream = null;

        if (route != null)
        {
            String tlsHostname = tlsBeginEx.hostname().asString();
            if (tlsHostname == null)
            {
                final TlsRouteExFW routeEx = route.extension().get(tlsRouteExRO::wrap);
                tlsHostname = routeEx.hostname().asString();
            }

            String tlsApplicationProtocol = tlsBeginEx.applicationProtocol().asString();
            if (tlsApplicationProtocol == null)
            {
                final TlsRouteExFW routeEx = route.extension().get(tlsRouteExRO::wrap);
                tlsApplicationProtocol = routeEx.applicationProtocol().asString();
            }

            final String networkName = route.target().asString();
            final long networkRef = route.targetRef();

            final long applicationId = begin.streamId();

            final LongSupplier writeFrameCounter = supplyWriteFrameCounter.apply(route);
            final LongSupplier readFrameCounter = supplyReadFrameCounter.apply(route);
            final LongConsumer writeBytesAccumulator = supplyWriteBytesAccumulator.apply(route);
            final LongConsumer readBytesAccumulator = supplyReadBytesAccumulator.apply(route);

            newStream = new ClientAcceptStream(
                tlsHostname,
                tlsApplicationProtocol,
                defaultRoute,
                applicationThrottle,
                applicationId,
                authorization,
                networkName,
                networkRef,
                writeFrameCounter,
                readFrameCounter,
                writeBytesAccumulator,
                readBytesAccumulator
                )::handleStream;
        }

        return newStream;
    }

    private MessageConsumer newConnectReplyStream(
        final BeginFW begin,
        final MessageConsumer networkReplyThrottle)
    {
        final long networkReplyId = begin.streamId();
        final long authorization =- begin.authorization();

        return new ClientConnectReplyStream(
                networkReplyThrottle,
                networkReplyId,
                authorization)::handleStream;
    }

    private RouteFW wrapRoute(
        int msgTypeId,
        DirectBuffer buffer,
        int index,
        int length)
    {
        return routeRO.wrap(buffer, index, index + length);
    }

    private final class ClientAcceptStream
    {
        private final String tlsHostname;
        private final String tlsApplicationProtocol;
        private final boolean defaultRoute;

        private final MessageConsumer applicationThrottle;
        private final long applicationId;
        private final long authorization;

        private final String networkName;
        private final MessageConsumer networkTarget;
        private final long networkRef;

        private final LongSupplier writeFrameCounter;
        private final LongSupplier readFrameCounter;
        private final LongConsumer writeBytesAccumulator;
        private final LongConsumer readBytesAccumulator;

        private SSLEngine tlsEngine;
        private MessageConsumer streamState;

        private long networkId;
        private EncryptMemoryManager networkMemoryManager;

        private ClientAcceptStream(
            String tlsHostname,
            String tlsApplicationProtocol,
            boolean defaultRoute,
            MessageConsumer applicationThrottle,
            long applicationId,
            long authorization,
            String networkName,
            long networkRef,
            LongSupplier writeFrameCounter,
            LongSupplier readFrameCounter,
            LongConsumer writeBytesAccumulator,
            LongConsumer readBytesAccumulator)
        {
            this.tlsHostname = tlsHostname;
            this.tlsApplicationProtocol = tlsApplicationProtocol;
            this.defaultRoute = defaultRoute;
            this.applicationThrottle = applicationThrottle;
            this.applicationId = applicationId;
            this.authorization = authorization;
            this.networkName = networkName;
            this.networkTarget = router.supplyTarget(networkName);
            this.networkRef = networkRef;
            this.writeFrameCounter = writeFrameCounter;
            this.readFrameCounter = readFrameCounter;
            this.writeBytesAccumulator = writeBytesAccumulator;
            this.readBytesAccumulator = readBytesAccumulator;
            this.streamState = this::beforeBegin;
        }

        private void handleStream(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
            streamState.accept(msgTypeId, buffer, index, length);
        }

        private void beforeBegin(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
            if (msgTypeId == BeginFW.TYPE_ID)
            {
                final BeginFW begin = beginRO.wrap(buffer, index, index + length);
                handleBegin(begin);
            }
            else
            {
//                doReset();
            }
        }

        private void afterBegin(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
            switch (msgTypeId)
            {
            case TransferFW.TYPE_ID:
                final TransferFW transfer = transferRO.wrap(buffer, index, index + length);
                handleTransfer(transfer);
                break;
            default:
//                doReset();  TODO
                break;
            }
        }

        private void handleBegin(
            BeginFW begin)
        {
            try
            {
                final String applicationName = begin.source().asString();
                final long applicationCorrelationId = begin.correlationId();
                final long authorization = begin.authorization();

                final long newNetworkId = supplyStreamId.getAsLong();
                final long newCorrelationId = supplyCorrelationId.getAsLong();

                final SSLEngine tlsEngine = context.createSSLEngine(tlsHostname, -1);
                tlsEngine.setUseClientMode(true);

                final SSLParameters tlsParameters = tlsEngine.getSSLParameters();
                tlsParameters.setEndpointIdentificationAlgorithm("HTTPS");
                if (tlsHostname != null)
                {
                    tlsParameters.setServerNames(asList(new SNIHostName(tlsHostname)));
                }

                if (tlsApplicationProtocol != null && !tlsApplicationProtocol.isEmpty())
                {
                    String[] applicationProtocols = new String[] { tlsApplicationProtocol };
                    tlsParameters.setApplicationProtocols(applicationProtocols);
                }

                tlsEngine.setSSLParameters(tlsParameters);

                this.networkMemoryManager = new EncryptMemoryManager(
                    memoryManager,
                    directBufferBuilderRO,
                    directBufferRW,
                    regionsRO,
                    transferCapacity,
                    networkId,
                    () -> 1,
                    i -> {});

                final ClientHandshake newHandshake = new ClientHandshake(
                    tlsEngine,
                    tlsApplicationProtocol,
                    defaultRoute,
                    networkName,
                    newNetworkId,
                    authorization,
                    applicationName,
                    applicationCorrelationId,
                    newCorrelationId,
                    this::handleThrottle,
                    applicationThrottle,
                    applicationId,
                    this::handleNetworkReplyDone);
//                    writeFrameCounter,
//                    readFrameCounter,
//                    writeBytesAccumulator,
//                    readBytesAccumulator);

                doBegin(networkTarget, newNetworkId, authorization, networkRef, newCorrelationId);
                router.setThrottle(networkName, newNetworkId, newHandshake::handleThrottle);

                this.tlsEngine = tlsEngine;
                this.networkId = newNetworkId;
                this.streamState = this::afterBegin;

                tlsEngine.beginHandshake();
            }
            catch (SSLException ex)
            {
//                doReset();
//                doAbort();
            }
        }

        private void handleTransfer(
            TransferFW transfer)
        {
            final ListFW<RegionFW> regions = transfer.regions();
            final int flags = transfer.flags();
//            regions.forEach(r -> readBytesAccumulator.accept(r.length()));
//            if (!regions.isEmpty())
//            {
//                readFrameCounter.getAsLong();
//            }

            processApplication(
                regions,
                transfer.authorization(),
                flags);

            if (isReset(flags))
            {
                handleApplicationReset();
            }
            else if(isFin(flags))
            {
                handleApplicationFin();
            }
        }

        private void processApplication(
            final ListFW<RegionFW> regions,
            final long authorization,
            final int flags)
        {
            // stage into buffer
            inAppByteBuffer.clear();

            regions.forEach(r ->
            {
                final long rAddress = memoryManager.resolve(r.address());
                final int length = r.length();
                view.wrap(rAddress, length);
                final int appByteBufferIndex = inAppByteBuffer.position();
                view.getBytes(0, inAppByteBuffer, appByteBufferIndex, length);
                inAppByteBuffer.position(appByteBufferIndex + length);
            });
            inAppByteBuffer.flip();

            try
            {
                while (inAppByteBuffer.hasRemaining() && !tlsEngine.isOutboundDone())
                {
                    outNetByteBuffer.clear();
                    final int maxPayloadSize = networkMemoryManager.maxPayloadSize(regions);
                    //    outNetByteBuffer.limit(maxPayloadSize);  TODO, need to check for buffer OVERFLOW,
                    // instead we are checking bytesProduced < maxPayload Size (if we do TODO need bookkeeping)

                    SSLEngineResult result = tlsEngine.wrap(inAppByteBuffer, outNetByteBuffer);
                    final int bytesProduced = result.bytesProduced();

                    if (maxPayloadSize < bytesProduced)
                    {
                        throw new IllegalArgumentException("transfer capacity exceeded");
                        // TODO: reset stream instead
                    }
                    outNetByteBuffer.flip();

                    if (inAppByteBuffer.hasRemaining())
                    {
                        doTransfer(
                            networkTarget,
                            networkId,
                            authorization,
                            EMPTY,
                            rb -> networkMemoryManager.packRegions(outNetByteBuffer, 0, bytesProduced, EMPTY_REGION_RO, rb));
                    }
                    else
                    {
                        doTransfer(
                            networkTarget,
                            networkId,
                            authorization,
                            EMPTY,
                            rb -> networkMemoryManager.packRegions(outNetByteBuffer, 0, bytesProduced, regions, rb));
                    }
                }
            }
            catch (SSLException ex)
            {
                // TODO testing
                doTransfer(networkTarget, networkId, authorization, RST);
            }
        }

        private void handleApplicationFin()
        {

            try
            {
//                doCloseOutbound(
//                        tlsEngine,
//                        networkTarget,
//                        networkId,
//                        authorization,
//                        this::handleNetworkReplyDone);
                throw new SSLException("Not implemented yet");
            }
            catch (SSLException ex)
            {
                doTransfer(networkTarget, networkId, authorization, RST);
            }
        }

        private void handleApplicationReset()
        {
            tlsEngine.closeOutbound();
            doTransfer(networkTarget, networkId, authorization, RST);
        }

        private void handleThrottle(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
            switch (msgTypeId)
            {
                case AckFW.TYPE_ID:
                    final AckFW ack = ackRO.wrap(buffer, index, index + length);
                    final ListFW<RegionFW> regions = ack.regions();
                    final int flags = ack.flags();
                    if (isReset(flags))
                    {
                        tlsEngine.closeOutbound();
                        doAck(applicationThrottle, applicationId, RST);
                    }
                    else if (!regions.isEmpty() || isFin(flags))
                    {
                        doAck(
                            applicationThrottle,
                            applicationId,
                            flags,
                            rsb -> regions.forEach(r -> rsb.item(rb -> rb.address(r.address())
                                                                         .length(r.length())
                                                                         .streamId(r.streamId()))));
                    }
                    break;
                default:
                    // ignore
                    break;
            }
        }
    }

    public final class ClientHandshake
    {
        private final SSLEngine tlsEngine;
        private final String applicationProtocol;
        private final boolean defaultRoute;

        private final String networkName;
        private final MessageConsumer networkTarget;
        private final long networkId;
        private final long networkAuthorization;
        private final MessageConsumer networkThrottle;

        private final MessageConsumer applicationThrottle;
        private final long applicationId;

        private final String applicationName;
        private final long applicationCorrelationId;
        private final long networkCorrelationId;

        private final Runnable networkReplyDoneHandler;

        private MessageConsumer networkReplyThrottle;
        private long networkReplyId;

        private Consumer<AckFW> windowHandler;
        private BiConsumer<HandshakeStatus, Consumer<SSLEngineResult>> statusHandler;

        private ClientHandshake(
            SSLEngine tlsEngine,
            String applicationProtocol,
            boolean defaultRoute,
            String networkName,
            long networkId,
            long authorization,
            String applicationName,
            long applicationCorrelationId,
            long networkCorrelationId,
            MessageConsumer networkThrottle,
            MessageConsumer applicationThrottle,
            long applicationId,
            Runnable networkReplyDoneHandler)
        {
            this.tlsEngine = tlsEngine;
            this.applicationProtocol = applicationProtocol;
            this.defaultRoute = defaultRoute;
            this.networkName = networkName;
            this.networkTarget = router.supplyTarget(networkName);
            this.networkId = networkId;
            this.networkAuthorization = authorization;
            this.applicationName = applicationName;
            this.applicationCorrelationId = applicationCorrelationId;
            this.networkCorrelationId = networkCorrelationId;
            this.networkThrottle = networkThrottle;
            this.windowHandler = null; // DPW TODO
            this.applicationThrottle = applicationThrottle;
            this.applicationId = applicationId;
            this.networkReplyDoneHandler = networkReplyDoneHandler;
//            this.writeFrameCounter = writeFrameCounter;
//            this.readFrameCounter = readFrameCounter;
//            this.writeBytesAccumulator = writeBytesAccumulator;
//            this.readBytesAccumulator = readBytesAccumulator;
        }

        @Override
        public String toString()
        {
            return String.format("%s [tlsEngine=%s]", getClass().getSimpleName(), tlsEngine);
        }

        private void onNetworkReply(
            MessageConsumer networkReplyThrottle,
            long networkReplyId,
            BiConsumer<HandshakeStatus, Consumer<SSLEngineResult>> statusHandler)
        {
            this.networkReplyThrottle = networkReplyThrottle;
            this.networkReplyId = networkReplyId;
            this.statusHandler = statusHandler;
//            this.windowHandler = this::afterNetworkReply; DPW TODO

//            statusHandler.accept(tlsEngine.getHandshakeStatus(), this::updateNetworkWindow);
        }

        private MessageConsumer doBeginApplicationReply(
            MessageConsumer applicationThrottle,
            long applicationReplyId)
        {
            final String applicationReplyName = applicationName;
            final String tlsPeerHost = tlsEngine.getPeerHost();

            String tlsApplicationProtocol0 = tlsEngine.getApplicationProtocol();
            if (tlsApplicationProtocol0 != null && tlsApplicationProtocol0.isEmpty())
            {
                tlsApplicationProtocol0 = null;
            }
            final String tlsApplicationProtocol = tlsApplicationProtocol0;

            final MessageConsumer applicationReply = router.supplyTarget(applicationReplyName);

//            doTlsBegin(applicationReply, applicationReplyId, 0L, applicationCorrelationId,
//                    tlsPeerHost, tlsApplicationProtocol);
            router.setThrottle(applicationReplyName, applicationReplyId, applicationThrottle);

            router.setThrottle(networkName, networkId, networkThrottle);

            return applicationReply;
        }

        private void handleThrottle(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
            switch (msgTypeId)
            {
            case AckFW.TYPE_ID:
                // TODO
//                windowHandler.accept(window);
//                handleReset(reset);
                break;
            default:
                // ignore
                break;
            }
        }

        private void handleReset(
            AckFW reset)
        {
            try
            {
                if (correlations.remove(networkCorrelationId) == null)
                {
//                    doReset();
                }
                tlsEngine.closeInbound();
            }
            catch (SSLException ex)
            {
                // ignore
            }
        }

        private void afterBegin(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
            switch (msgTypeId)
            {
//            case WriteFW.TYPE_ID:
//                // TODO
//                final DataFW data = dataRO.wrap(buffer, index, index + length);
//                handleData(data);
//                break;
//            case EndFW.TYPE_ID:
//                final EndFW end = endRO.wrap(buffer, index, index + length);
//                handleEnd(end);
//                break;
//            case AbortFW.TYPE_ID:
//                final AbortFW abort = abortRO.wrap(buffer, index, index + length);
//                handleAbort(abort);
//                break;
            default:
//                doReset();
                break;
            }
        }

        private void handleData(
            TransferFW write)
        {
            // DPW TODO
//            try
//            {
//                final ListFW<RegionFW> payload = write.regions();
//                final int payloadSize = payload.sizeof();
//
//                loop:
//                while (inNetByteBuffer.hasRemaining() && !tlsEngine.isInboundDone())
//                {
//                    outAppByteBuffer.rewind();
//                    SSLEngineResult result = tlsEngine.unwrap(inNetByteBuffer, outAppByteBuffer);
//
//                    if (outAppByteBuffer.position() != 0)
//                    {
//                        doReset(networkReplyThrottle, networkReplyId);
//                        break loop;
//                    }
//
//                    switch (result.getStatus())
//                    {
//                    case BUFFER_UNDERFLOW:
//                        final int totalBytesConsumed = inNetByteBuffer.position() - inNetByteBufferPosition;
//                        final int totalBytesRemaining = inNetByteBuffer.remaining();
//                        alignSlotBuffer(inNetBuffer, totalBytesConsumed, totalBytesRemaining);
//                        networkReplySlotOffset = totalBytesRemaining;
//                        break loop;
//                    default:
//                        networkReplySlotOffset = 0;
//                        statusHandler.accept(result.getHandshakeStatus(), this::updateNetworkWindow);
//                        break;
//                    }
//                }
//
//                networkReplyBudgetConsumer.accept(
//                        networkReplyBudgetSupplier.getAsInt() + networkReplyBudgetCredit);
//                doWindow(networkReplyThrottle, networkReplyId, networkReplyBudgetCredit);
//            }
//            catch (SSLException ex)
//            {
//                networkReplySlotOffset = 0;
//                doReset(networkReplyThrottle, networkReplyId);
//                doAbort(networkTarget, networkId, networkAuthorization);
//            }
//            finally
//            {
//                if (networkReplySlotOffset == 0 && networkReplySlot != NO_SLOT)
//                {
//                    networkPool.release(networkReplySlot);
//                    networkReplySlot = NO_SLOT;
//                }
            }
        }

        private void handleEnd()
        {
            // DPW TODO
//            try
//            {
//                doCloseOutbound(tlsEngine, networkTarget, networkId, networkPaddingSupplier.getAsInt(),
//                        networkAuthorization, networkReplyDoneHandler);
//            }
//            catch (SSLException ex)
//            {
//                doAbort(networkTarget, networkId, networkAuthorization);
//            }
//            finally
//            {
//                doReset(networkThrottle, networkId);
//            }
        }

        private void handleAbort()
        {
            // DPW TODO
//            correlations.remove(networkCorrelationId);
//            tlsEngine.closeOutbound();
//            doAbort(networkTarget, networkId, networkAuthorization);
        }


    private final class ClientConnectReplyStream
    {
        private final MessageConsumer networkReplyThrottle;
        private final long networkReplyId;

        private MessageConsumer networkTarget;
        private long networkId;
        private long networkAuthorization;

        private SSLEngine tlsEngine;

        private MessageConsumer applicationReply;
        private long applicationReplyId;
        private final long applicationReplyAuthorization;
        private ObjectLongBiFunction<MessageConsumer, MessageConsumer> doBeginApplicationReply;

        private MessageConsumer streamState;

        private Runnable networkReplyDoneHandler;
        private String applicationProtocol;
        private boolean defaultRoute;

        private LongSupplier writeFrameCounter;
        private LongSupplier readFrameCounter;
        private LongConsumer writeBytesAccumulator;
        private LongConsumer readBytesAccumulator;

        private ClientConnectReplyStream(
            MessageConsumer networkReplyThrottle,
            long networkReplyId,
            long networkReplyAuthorization)
        {
            this.networkReplyThrottle = networkReplyThrottle;
            this.networkReplyId = networkReplyId;
            this.applicationReplyAuthorization = networkReplyAuthorization;
            this.streamState = this::beforeHandshake;
        }

        private void handleStream(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
            streamState.accept(msgTypeId, buffer, index, length);
        }

        private void beforeHandshake(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
            if (msgTypeId == BeginFW.TYPE_ID)
            {
                final BeginFW begin = beginRO.wrap(buffer, index, index + length);
                handleBegin(begin);
            }
            else
            {
                doReset(networkReplyThrottle, networkReplyId);
            }
        }

        private void afterHandshake(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
//            switch (msgTypeId)
//            {
//            case DataFW.TYPE_ID:
//                final DataFW data = dataRO.wrap(buffer, index, index + length);
//                handleData(data);
//                break;
//            case EndFW.TYPE_ID:
//                final EndFW end = endRO.wrap(buffer, index, index + length);
//                handleEnd(end);
//                break;
//            case AbortFW.TYPE_ID:
//                final AbortFW abort = abortRO.wrap(buffer, index, index + length);
//                handleAbort(abort);
//                break;
//            default:
//                doReset(networkReplyThrottle, networkReplyId);
//                break;
//            }
        }

        private void handleBegin(
            BeginFW begin)
        {
            final long sourceRef = begin.sourceRef();
            final long correlationId = begin.correlationId();

            final ClientHandshake handshake = sourceRef == 0L ? correlations.remove(correlationId) : null;
            if (handshake != null)
            {
                this.tlsEngine = handshake.tlsEngine;
                this.applicationProtocol = handshake.applicationProtocol;
                this.defaultRoute = handshake.defaultRoute;
                this.networkTarget = handshake.networkTarget;
                this.networkId = handshake.networkId;
                this.networkAuthorization = handshake.networkAuthorization;
                this.doBeginApplicationReply = handshake::doBeginApplicationReply;
                this.streamState = handshake::afterBegin;
                this.networkReplyDoneHandler = handshake.networkReplyDoneHandler;
//                this.writeFrameCounter = handshake.writeFrameCounter;
//                this.readFrameCounter = handshake.readFrameCounter;
//                this.writeBytesAccumulator = handshake.writeBytesAccumulator;
//                this.readBytesAccumulator = handshake.readBytesAccumulator;

//                doWindow(networkReplyThrottle, networkReplyId, networkReplyBudget, networkReplyPadding);

                handshake.onNetworkReply(
                    networkReplyThrottle,
                    networkReplyId,
                    this::handleStatus);
            }
            else
            {
                doReset(networkReplyThrottle, networkReplyId);
            }
        }

        private void handleData(
            TransferFW data)
        {
//            try
//            {
//                final OctetsFW payload = data.payload();
//                final int payloadSize = payload.sizeof();
//
//                final MutableDirectBuffer inNetBuffer = networkPool.buffer(networkReplySlot);
//                inNetBuffer.putBytes(networkReplySlotOffset, payload.buffer(), payload.offset(), payloadSize);
//                networkReplySlotOffset += payloadSize;
//
//                unwrapNetworkBufferData();
//            }
//            catch (SSLException ex)
//            {
//                doReset(networkReplyThrottle, networkReplyId);
//                doAbort(applicationReply, applicationReplyId, applicationReplyAuthorization);
//            }
        }

        private void unwrapNetworkBufferData()
        {
            try
            {
//                loop:
//                while (inNetByteBuffer.hasRemaining() && !tlsEngine.isInboundDone())
//                {
//                    final ByteBuffer outAppByteBuffer = applicationPool.byteBuffer(applicationReplySlot);
//                    outAppByteBuffer.position(outAppByteBuffer.position() + applicationReplySlotOffset);
//
//                    SSLEngineResult result = tlsEngine.unwrap(inNetByteBuffer, outAppByteBuffer);
//
//                    switch (result.getStatus())
//                    {
//                    case BUFFER_OVERFLOW:
//                    case BUFFER_UNDERFLOW:
//                        final int totalBytesConsumed = inNetByteBuffer.position() - inNetByteBufferPosition;
//                        final int totalBytesRemaining = inNetByteBuffer.remaining();
//                        alignSlotBuffer(inNetBuffer, totalBytesConsumed, totalBytesRemaining);
//                        networkReplySlotOffset = totalBytesRemaining;
//                        if (networkReplySlotOffset == networkPool.slotCapacity() &&
//                                result.getStatus() == BUFFER_UNDERFLOW)
//                        {
//                            networkReplySlotOffset = 0;
//                            tlsEngine.closeInbound();
//                            doReset(networkReplyThrottle, networkReplyId);
//                            doAbort(applicationReply, applicationReplyId, applicationReplyAuthorization);
//                        }
//                        else
//                        {
//                            final int networkWindowBytesUpdate =
//                                Math.max(networkPool.slotCapacity() - networkReplySlotOffset - networkReplyBudget, 0);
//
//                            if (networkWindowBytesUpdate > 0)
//                            {
//                                networkReplyBudget += networkWindowBytesUpdate;
//                                doWindow(networkReplyThrottle, networkReplyId, networkWindowBytesUpdate,
//                                        networkReplyPadding);
//                            }
//                        }
//                        break loop;
//                    default:
//                        networkReplySlotOffset = 0;
//                        applicationReplySlotOffset += result.bytesProduced();
//                        handleStatus(result.getHandshakeStatus(), r -> {});
//                        break;
//                    }
//                }

//                handleFlushAppData();
            }
//            catch (SSLException ex)
//            {
//                doReset(networkReplyThrottle, networkReplyId);
//                doAbort(applicationReply, applicationReplyId, applicationReplyAuthorization);
//            }
            finally
            {
            }
        }

        private void handleEnd()
        {
            // DPW TODO
            if (!tlsEngine.isInboundDone())
            {
                try
                {
                    tlsEngine.closeInbound();
                    doEnd(applicationReply, applicationReplyId, applicationReplyAuthorization);
                }
                catch (SSLException ex)
                {
                    doAbort(applicationReply, applicationReplyId, applicationReplyAuthorization);
                }
            }
        }

        private void handleAbort()
        {
            // DPW TODO
            try
            {
                tlsEngine.closeInbound();
            }
            catch (SSLException ex)
            {
                // ignore and clean up
            }
            finally
            {
                doAbort(applicationReply, applicationReplyId, applicationReplyAuthorization);
            }
        }

        private HandshakeStatus handleStatus(
            HandshakeStatus status,
            Consumer<SSLEngineResult> resultHandler)
        {
            loop:
            for (;;)
            {
                switch (status)
                {
                case NEED_TASK:
                    for (Runnable runnable = tlsEngine.getDelegatedTask();
                            runnable != null;
                            runnable = tlsEngine.getDelegatedTask())
                    {
                        runnable.run();
                    }

                    status = tlsEngine.getHandshakeStatus();
                    break;
                case NEED_WRAP:
                    try
                    {
                        outNetByteBuffer.rewind();
                        SSLEngineResult result = tlsEngine.wrap(EMPTY_BYTE_BUFFER, outNetByteBuffer);
                        resultHandler.accept(result);
                        flushNetwork(
                                tlsEngine,
                                result.bytesProduced(),
                                networkTarget,
                                networkId,
                                networkAuthorization,
                                networkReplyDoneHandler);
                        status = result.getHandshakeStatus();
                    }
                    catch (SSLException ex)
                    {
                        // lambda interface cannot throw checked exception
                        rethrowUnchecked(ex);
                    }
                    break;
                case FINISHED:
                    handleFinished();
                    status = tlsEngine.getHandshakeStatus();
                    break;
                default:
                    break loop;
                }
            }

            return status;
        }

        private void handleFinished()
        {
            String tlsApplicationProtocol = tlsEngine.getApplicationProtocol();
            if ((tlsApplicationProtocol.equals("") && defaultRoute)
                    || Objects.equals(tlsApplicationProtocol, applicationProtocol))
            {
                // no ALPN negotiation && default route OR
                // negotiated protocol from ALPN matches with our route
                final long newApplicationReplyId = supplyStreamId.getAsLong();
                this.applicationReply = this.doBeginApplicationReply.apply(this::handleThrottle, newApplicationReplyId);
                this.applicationReplyId = newApplicationReplyId;

                this.streamState = this::afterHandshake;
                this.doBeginApplicationReply = null;
            }
            else
            {
                doReset(networkReplyThrottle, networkReplyId);
            }
        }

        private void handleThrottle(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
            // DPW TODO
//            switch (msgTypeId)
//            {
//            case WindowFW.TYPE_ID:
//                final WindowFW window = windowRO.wrap(buffer, index, index + length);
//                handleWindow(window);
//                break;
//            case ResetFW.TYPE_ID:
//                final ResetFW reset = resetRO.wrap(buffer, index, index + length);
//                handleReset(reset);
//                break;
//            default:
//                // ignore
//                break;
//            }
        }

        private void handleWindow(
            AckFW ack)
        {

        }

        private void handleReset()
        {
            try
            {
                tlsEngine.closeInbound();
            }
            catch (SSLException ex)
            {
                // ignore and clean up
            }
            finally
            {
                doReset(networkReplyThrottle, networkReplyId);
            }
        }
    }

    private void flushNetwork(
        SSLEngine tlsEngine,
        int bytesProduced,
        MessageConsumer networkTarget,
        long networkId,
        long authorization,
        Runnable networkReplyDoneHandler)
//        LongSupplier writeFrameCounter,
//        LongConsumer writeBytesAccumulator)
    {
        if (bytesProduced > 0)
        {
//            final OctetsFW outNetOctets = transferRW.wrap(outNetBuffer, 0, bytesProduced);
//            doData(networkTarget, networkId, authorization, outNetOctets);
        }

        if (tlsEngine.isOutboundDone())
        {
            doEnd(networkTarget, networkId, authorization);
            networkReplyDoneHandler.run();
        }
    }

    private void doTlsBegin(
        MessageConsumer target,
        long targetId,
        long targetRef,
        long correlationId,
        String hostname,
        String applicationProtocol)
    {
        final BeginFW begin = beginRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                                     .streamId(targetId)
                                     .source("tls")
                                     .sourceRef(targetRef)
                                     .correlationId(correlationId)
                                     .extension(e -> e.set(visitTlsBeginEx(hostname, applicationProtocol)))
                                     .build();

        target.accept(begin.typeId(), begin.buffer(), begin.offset(), begin.sizeof());
    }

    private Flyweight.Builder.Visitor visitTlsBeginEx(
        String hostname,
        String applicationProtocol)
    {
        return (buffer, offset, limit) ->
            tlsBeginExRW.wrap(buffer, offset, limit)
                        .hostname(hostname)
                        .applicationProtocol(applicationProtocol)
                        .build()
                        .sizeof();
    }


//    private void doCloseOutbound(
//        SSLEngine tlsEngine,
//        MessageConsumer networkTarget,
//        long networkId,
//        long authorization,
//        Runnable networkReplyDoneHandler,
//        LongSupplier writeFrameCounter,
//        LongConsumer writeBytesAccumulator) throws SSLException
//    {
//        tlsEngine.closeOutbound();
//        outNetByteBuffer.rewind();
//        SSLEngineResult result = tlsEngine.wrap(inAppByteBuffer, outNetByteBuffer);
//        flushNetwork(tlsEngine, result.bytesProduced(), networkTarget, networkId, authorization,
//                networkReplyDoneHandler);
//    }

    private void doBegin(
        final MessageConsumer target,
        final long targetId,
        final long authorization,
        final long targetRef,
        final long correlationId)
    {
        final BeginFW begin = beginRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                .streamId(targetId)
                .authorization(authorization)
                .source("tls")
                .sourceRef(targetRef)
                .correlationId(correlationId)
                .build();

        target.accept(begin.typeId(), begin.buffer(), begin.offset(), begin.sizeof());
    }

    private void doTransfer(
        final MessageConsumer target,
        final long targetId,
        final long authorization,
        final int flags,
        final Consumer<Builder<RegionFW.Builder, RegionFW>> mutator)
    {
        final TransferFW transfer = transferRW.wrap(writeBuffer, 0, writeBuffer.capacity())
            .streamId(targetId)
            .authorization(authorization)
            .flags(flags)
            .regions(mutator)
            .build();
        target.accept(transfer.typeId(), transfer.buffer(), transfer.offset(), transfer.sizeof());
    }

    private void doTransfer(
        final MessageConsumer target,
        final long targetId,
        final long authorization,
        final int flags)
    {
        final TransferFW transfer = transferRW.wrap(writeBuffer, 0, writeBuffer.capacity())
            .streamId(targetId)
            .authorization(authorization)
            .flags(flags)
            .build();
        target.accept(transfer.typeId(), transfer.buffer(), transfer.offset(), transfer.sizeof());
    }


    private void doAck(
            final MessageConsumer throttle,
            final long throttleId,
            final int flags,
            Consumer<Builder<RegionFW.Builder, RegionFW>> mutator)
    {
        final AckFW ack = ackRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                               .streamId(throttleId)
                               .flags(flags)
                               .regions(mutator)
                               .build();
        throttle.accept(ack.typeId(), ack.buffer(), ack.offset(), ack.sizeof());
    }

    private void doAck(
        final MessageConsumer throttle,
        final long throttleId,
        final int flags)
    {
        final AckFW ack = ackRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                .streamId(throttleId)
                .flags(flags)
                .build();
        throttle.accept(ack.typeId(), ack.buffer(), ack.offset(), ack.sizeof());
    }


    private void doCloseInbound(
        final SSLEngine tlsEngine) throws SSLException
    {
        tlsEngine.closeInbound();
    }

    private ByteBuffer stageInAppBuffer(
        LongArrayList regionAddresses,
        IntArrayList regionLengths)
    {
        // TODO better loop
        for (int i = 0; i < regionAddresses.size(); i++)
        {
            int position = inAppByteBuffer.position();
            long addr = regionAddresses.get(i);
            int length = regionLengths.get(i);
            view.wrap(memoryManager.resolve(addr), length);
            view.getBytes(0, inAppByteBuffer, position, length);
            inAppByteBuffer.position(position + length);
        }
        inAppByteBuffer.flip();
        return inAppByteBuffer;
    }

}
