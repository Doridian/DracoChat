package me.draconia.chat.client.types;

import me.draconia.chat.client.gui.FormMain;
import me.draconia.chat.types.User;

public class ClientUser extends User {
    ClientUser(String login) {
        super(login);
    }

    @Override
    public void setNickname(String nickname) {
        super.setNickname(nickname);
        FormMain.instance.refreshTabTitle(this);
    }
}
