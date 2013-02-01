package me.draconia.chat.types;

public abstract class UserFactory {
    public static UserFactory instance;

    public static void setInstance(UserFactory instance) {
        UserFactory.instance = instance;
        User systemUser = instance.createFromLogin("[system]");
        systemUser.setNickname("[SYSTEM]");
        User.SYSTEM = systemUser;
    }

    public final User getFromLogin(String login) {
        login = login.toLowerCase();
        if(login.equals("[system]")) {
            return User.SYSTEM;
        }
        return createFromLogin(login);
    }

    protected abstract User createFromLogin(String login);
}
