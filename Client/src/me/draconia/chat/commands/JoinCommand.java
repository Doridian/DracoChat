package me.draconia.chat.commands;

import me.draconia.chat.client.types.ClientChannel;
import me.draconia.chat.types.ChannelFactory;
import me.draconia.chat.types.MessageContext;
import me.draconia.chat.types.User;

@BaseCommand.Names("join")
public class JoinCommand extends BaseClientCommand {
    @Override
    public void run(User user, MessageContext messageContext, String[] args, String argStr) throws Exception {
        String arg = args[0];
        if(arg.charAt(0) == '#') {
            arg = arg.substring(1);
        }
        ClientChannel clientChannel = (ClientChannel)ChannelFactory.instance.createFromName(arg);
        clientChannel.join();
    }
}
