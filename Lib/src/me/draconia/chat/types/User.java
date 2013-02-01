package me.draconia.chat.types;

import java.io.Serializable;

public class User implements MessageContext, Serializable {
    public static final long serialVersionUID = -1L;

    public final String login;
    private String nickname;

    protected static User SYSTEM;

    public static User getSYSTEM() {
        return SYSTEM;
    }

    protected User(String login) {
        this.login = login;
    }

    @Override
    public int hashCode() {
        return login.hashCode();
    }

    public String getNickname() {
        return nickname;
    }

    public void setNickname(String nickname) {
        this.nickname = nickname;
    }

    public String getDisplayName() {
        if(this.nickname == null) {
            return this.login;
        } else {
            return this.nickname;
        }
    }

    @Override
    public boolean equals(Object obj) {
        if(obj == null)
            return false;
        if(!(obj instanceof User))
            return false;
        return login.equals(((User)obj).login);
    }

    @Override
    public String toString() {
        return "U#" + login;
    }

    @Override
    public String getContextName() {
        if(this.nickname == null) {
            return this.login;
        } else {
            return this.login + " [" + this.nickname + "]";
        }
    }
}
