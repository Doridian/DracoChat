package me.draconia.chat.server;

import me.draconia.chat.types.Channel;
import me.draconia.chat.types.ChannelFactory;

import java.util.HashMap;

public class ServerChannelFactory extends ChannelFactory {
	private final HashMap<String, Channel> channelsMap = new HashMap<String, Channel>();

	@Override
	public Channel createFromName(String name) {
		Channel ret = channelsMap.get(name);
		if (ret != null)
			return ret;
		ret = new ServerChannel(name);
		channelsMap.put(name, ret);
		return ret;
	}
}
