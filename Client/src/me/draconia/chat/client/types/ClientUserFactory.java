package me.draconia.chat.client.types;

import me.draconia.chat.types.User;
import me.draconia.chat.types.UserFactory;

import java.util.HashMap;

public class ClientUserFactory extends UserFactory {
    private final HashMap<String, User> userMap = new HashMap<String, User>();

    @Override
    protected User createFromLogin(String login) {
        User ret = userMap.get(login);
        if(ret != null)
            return ret;
        ret = new ClientUser(login);
        userMap.put(login, ret);
        return ret;
    }
}
