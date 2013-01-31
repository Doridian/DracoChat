package me.draconia.chat.types;

public class User implements MessageContext {
    public final String login;
    private String nickname;
    private String contextName;

    protected static User SYSTEM;

    public static User getSYSTEM() {
        return SYSTEM;
    }

    protected User(String login) {
        this.login = login;
        this.contextName = login;
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
        if(this.nickname == null) {
            this.contextName = this.login;
        } else {
            this.contextName = this.login + " [" + this.nickname + "]";
        }
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
        return contextName;
    }
}
