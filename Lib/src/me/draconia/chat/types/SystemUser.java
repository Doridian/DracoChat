package me.draconia.chat.types;

public class SystemUser extends User {
    protected SystemUser() {
        super("[SYSTEM]");
    }

    @Override
    public String getNickname() {
        return "[SYSTEM]";
    }

    @Override
    public String getContextName() {
        return "[SYSTEM]";
    }

    @Override
    public String toString() {
        return "S#SYSTEM";
    }

    @Override
    public boolean equals(Object obj) {
        return (obj instanceof SystemUser);
    }

    @Override
    public int hashCode() {
        return 0;
    }

    @Override
    public void setNickname(String nickname) { }
}
