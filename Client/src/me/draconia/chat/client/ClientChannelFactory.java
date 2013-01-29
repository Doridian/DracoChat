package me.draconia.chat.client;

import me.draconia.chat.types.Channel;
import me.draconia.chat.types.ChannelFactory;

import java.util.HashMap;

public class ClientChannelFactory extends ChannelFactory {
    private HashMap<String, Channel> channelsMap = new HashMap<String, Channel>();

    @Override
    public Channel createFromName(String name) {
        Channel ret = channelsMap.get(name);
        if(ret != null)
            return ret;
        ret = new ClientChannel(name);
        channelsMap.put(name, ret);
        return ret;
    }
}
