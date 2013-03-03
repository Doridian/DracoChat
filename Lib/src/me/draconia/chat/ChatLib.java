package me.draconia.chat;

import me.draconia.chat.net.PacketHandler;
import me.draconia.chat.net.PacketReplayingDecoder;
import me.draconia.chat.net.packets.Packet;
import me.draconia.chat.types.ChannelFactory;
import me.draconia.chat.types.UserFactory;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelPipelineFactory;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.handler.ssl.SslHandler;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

public class ChatLib {
	public static final int PROTOCOL_VERSION = 2;

	public static ChannelPipelineFactory initialize(final SSLContext sslContext, final boolean clientMode, final PacketHandler packetHandler, final Packet.Side side, final UserFactory userFactory, final ChannelFactory channelFactory) {
		Packet.initialize(side);
		UserFactory.setInstance(userFactory);
		ChannelFactory.instance = channelFactory;

		return new ChannelPipelineFactory() {
			@Override
			public ChannelPipeline getPipeline() throws Exception {
				ChannelPipeline pipeline = Channels.pipeline();

				SSLEngine sslEngine = sslContext.createSSLEngine();
				sslEngine.setUseClientMode(clientMode);
				pipeline.addLast("ssl", new SslHandler(sslEngine));
				pipeline.addLast("framer", new PacketReplayingDecoder());
				pipeline.addLast("handler", packetHandler);

				return pipeline;
			}
		};
	}
}
