package me.draconia.chat.server;

import me.draconia.chat.ChatLib;
import me.draconia.chat.commands.BaseServerCommand;
import me.draconia.chat.net.PacketHandler;
import me.draconia.chat.net.Packets;
import me.draconia.chat.net.packets.*;
import me.draconia.chat.types.Message;
import me.draconia.chat.types.TextMessage;
import me.draconia.chat.types.UserFactory;
import org.jboss.netty.channel.*;
import org.jboss.netty.handler.ssl.SslHandler;

import java.io.IOException;
import java.nio.channels.ClosedChannelException;
import java.util.Set;

public class ServerPacketHandler extends PacketHandler {
    @Override
    public void packetReceived(ChannelHandlerContext ctx, Packet packet) throws Exception {
        final int packetID = packet.getID();

        Object attach = ctx.getAttachment();
        final ServerUser currentUser;
        if(attach != null) {
            currentUser = (ServerUser)attach;
        } else if(packetID != Packets.PING && packetID != Packets.DISCONNECT && packetID != Packets.LOGIN) {
            kickChannel(ctx, "Log in first!");
            return;
        } else {
            currentUser = null;
        }

        switch (packetID) {
            case Packets.PING:
                PacketPingPong packetPingPong = (PacketPingPong)packet;
                if(packetPingPong.id > 0) {
                    packetPingPong.id = -packetPingPong.id;
                    ctx.getChannel().write(packetPingPong.getData());
                } else {
                    //We got a response...DEAL WITH IT HERE
                }
                break;
            case Packets.LOGIN:
                if(currentUser != null) {
                    kickChannel(ctx, "Already logged in!");
                    return;
                }
                PacketLoginRequest packetLoginRequest = (PacketLoginRequest)packet;
                if(packetLoginRequest.version != ChatLib.PROTOCOL_VERSION) {
                    kickChannel(ctx, "Wrong version!");
                    return;
                }
                ServerUser serverUser = (ServerUser)UserFactory.instance.getFromLogin(packetLoginRequest.username);
                if(serverUser == null) {
                    kickChannel(ctx, "Internal error");
                    return;
                }
                if(!serverUser.hasPassword()) {
                    serverUser.setPassword(packetLoginRequest.password);
                    loginReply(ctx, serverUser, true, "Welcome, new user :3");
                } else if(!serverUser.checkPassword(packetLoginRequest.password)) {
                    loginReply(ctx, serverUser, false, "Wrong password!");
                    return;
                } else {
                    loginReply(ctx, serverUser, true, "Welcome back :3");
                }
                final Channel oldChannel = serverUser.getChannel();
                serverUser.setChannel(ctx.getChannel());
                if(oldChannel != null) {
                    kickChannel(oldChannel, "Logged in from a different location");
                    serverUser.disconnected(oldChannel);
                }
                ctx.setAttachment(serverUser);
                System.out.println("[LOGIN] " + serverUser.login + " joined the server!");
                break;
            case Packets.DISCONNECT:
                ctx.getChannel().close();
                break;
            case Packets.NICK_GET:
                PacketNickgetRequest packetNickgetRequest = (PacketNickgetRequest)packet;
                PacketNickgetResponse packetNickgetResponse = new PacketNickgetResponse();
                packetNickgetResponse.users = packetNickgetRequest.users;
                packetNickgetResponse.nicknames = new String[packetNickgetRequest.users.length];
                for(int i = 0; i < packetNickgetRequest.users.length; i++) {
                    packetNickgetResponse.nicknames[i] = packetNickgetRequest.users[i].getNickname();
                }
                currentUser.sendPacket(packetNickgetResponse);
                break;
            case Packets.NICK_SET:
                PacketNickset packetNickset = (PacketNickset)packet;
                currentUser.setNickname(packetNickset.nickname);
                currentUser.sendPacket(packetNickset);
                break;
            case Packets.MESSAGE:
                Message message = ((PacketMessageToServer)packet).message;
                if(message instanceof TextMessage) {
                    TextMessage textMessage = (TextMessage)message;
                    if(message.type == TextMessage.TYPE_SYSTEM || message.type == TextMessage.TYPE_SYSTEM_ERROR) {
                        kickChannel(ctx, "Nice try");
                        return;
                    } else if(textMessage.content.charAt(0) == '/') {
                        if(message.context instanceof ServerChannel) {
                            ServerChannel serverChannel = (ServerChannel) message.context;
                            if(!serverChannel.getUsers().contains(currentUser)) {
                                currentUser.sendSystemError("Cannot send command to channel #" + serverChannel.name + " (you are not in that channel)");
                            }
                        }
                        if(!BaseServerCommand.runCommand(currentUser, message.context, textMessage.content.substring(1))) {
                            currentUser.sendSystemError("[ERROR] Command not found");
                        }
                        return;
                    }
                }

                message.timestamp = System.currentTimeMillis();
                message.from = currentUser;

                PacketMessageToClient packetMessageToClient = new PacketMessageToClient();
                packetMessageToClient.message = message;

                if(message.context instanceof ServerChannel) {
                    ServerChannel serverChannel = (ServerChannel) message.context;
                    Set<ServerUser> channelUsers = serverChannel.getUsers();
                    if(channelUsers.contains(currentUser)) {
                        for(ServerUser user : channelUsers) {
                            if(!user.equals(currentUser)) user.sendPacket(packetMessageToClient);
                        }
                    } else {
                        currentUser.sendSystemError("Cannot send message to channel #" + serverChannel.name + " (you are not in that channel)");
                    }
                } else if(packetMessageToClient.message.context instanceof ServerUser) {
                    ((ServerUser) packetMessageToClient.message.context).sendPacket(packetMessageToClient);
                } else {
                    //TODO: Handle this [chat commands and stuff]
                }
                break;
            case Packets.CHANNEL_ACTION:
                PacketChannelAction packetChannelAction = (PacketChannelAction)packet;
                packetChannelAction.user = currentUser;
                ServerChannel serverChannel = (ServerChannel)packetChannelAction.channel;
                switch(packetChannelAction.action) {
                    case PacketChannelAction.ACTION_JOIN:
                        if(serverChannel.checkPassword(null)) {
                            serverChannel.joinUser(currentUser);
                        } else {
                            packetChannelAction.action = PacketChannelAction.ACTION_JOIN_DECLINED;
                            currentUser.sendPacket(packetChannelAction);
                        }
                        break;
                    case PacketChannelAction.ACTION_LEAVE:
                        serverChannel.leaveUser(currentUser);
                        break;
                }
                break;
            default:
                kickChannel(ctx, "Invalid packet!");
                break;
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, ExceptionEvent e) throws Exception {
        if(e.getCause() instanceof ClosedChannelException || e.getCause() instanceof IOException)
            return;
        e.getCause().printStackTrace();
    }

    @Override
    public void channelConnected(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
        final SslHandler sslHandler = ctx.getPipeline().get(SslHandler.class);
        sslHandler.handshake();
    }

    private void loginReply(ChannelHandlerContext ctx, ServerUser serverUser, boolean success, String message) {
        PacketLoginResponse packetLoginResponse = new PacketLoginResponse();
        packetLoginResponse.success = success;
        packetLoginResponse.message = message;
        packetLoginResponse.nickname = serverUser.getNickname();
        ctx.getChannel().write(packetLoginResponse.getData());
    }

    private void kickChannel(ChannelHandlerContext ctx, String message) {
        kickChannel(ctx.getChannel(), message);
    }

    private void kickChannel(Channel channel, String message) {
        PacketDisconnect packetDisconnect = new PacketDisconnect();
        packetDisconnect.message = message;
        channel.write(packetDisconnect.getData()).addListener(ChannelFutureListener.CLOSE);
    }
}
