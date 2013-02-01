package me.draconia.chat.client.types;

import me.draconia.chat.client.ClientLib;
import me.draconia.chat.client.gui.FormMain;
import me.draconia.chat.types.User;

public class ClientUser extends User {
    private transient byte state;

    ClientUser(String login) {
        super(login);
    }

    @Override
    public void setNickname(String nickname) {
        super.setNickname(nickname);
        FormMain.instance.refreshClientUserNickname(this);
    }

    public void setState(byte state) {
        this.state = state;

        if(this.equals(ClientLib.myUser))
            return;

        final String stateStr;
        switch (this.state) {
            case User.STATE_ONLINE:
                stateStr = "Online";
                break;
            case User.STATE_OFFLINE:
                stateStr = "Offline";
                break;
            default:
                stateStr = "Unknown";
                break;
        }
        FormMain.instance.getChatTab(this).addText("[STATE] " + getDisplayName() + " is now " + stateStr);
    }

    @Override
    public byte getState() {
        return state;
    }
}
