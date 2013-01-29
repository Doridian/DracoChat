package me.draconia.chat.commands;

import me.draconia.chat.net.packets.PacketMessageToClient;
import me.draconia.chat.server.ServerUser;
import me.draconia.chat.types.Message;
import me.draconia.chat.types.MessageContext;
import me.draconia.chat.types.TextMessage;
import me.draconia.chat.types.User;

public abstract class BaseServerCommand extends BaseCommand {
    @Override
    public final void commandError(User user, MessageContext messageContext, Exception error) {
        TextMessage message = new TextMessage();
        message.from = User.getSYSTEM();
        message.context = messageContext;
        message.type = TextMessage.TYPE_SYSTEM_ERROR;
        message.content = "[ERROR] " + error.getMessage();
        PacketMessageToClient packetMessageToClient = new PacketMessageToClient();
        packetMessageToClient.message = message;
        ((ServerUser)user).sendPacket(packetMessageToClient);
    }
}
