package me.draconia.chat.commands;

import me.draconia.chat.types.MessageContext;
import me.draconia.chat.types.User;
import me.draconia.chat.util.IntUtils;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.HashMap;
import java.util.List;

public abstract class BaseCommand {
    @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE) protected @interface Names { String[] value(); }

    public abstract void run(User user, MessageContext messageContext, String[] args, String argStr) throws Exception;

    public abstract void commandError(User user, MessageContext messageContext, Exception error);

    private final static HashMap<String, BaseCommand> commands;
    static {
        commands = new HashMap<String, BaseCommand>();

        List<Class<? extends BaseCommand>> commandClasses = IntUtils.getSubClasses(BaseCommand.class, BaseCommand.class.getPackage().getName());
        for(Class<? extends BaseCommand> commandCls : commandClasses) {
            if(!commandCls.isAnnotationPresent(Names.class))
                continue;
            try {
                BaseCommand command = commandCls.getConstructor().newInstance();
                String[] names = commandCls.getAnnotation(Names.class).value();

                for(String name : names) {
                    commands.put(name.toLowerCase(), command);
                    System.out.println("[CMD] Loaded command " + commandCls.getSimpleName() + " for /" + name);
                }
            } catch(Exception e) {
                System.out.println("[ERROR] Command " + commandCls.getSimpleName() + " failed to load because: " + e.getMessage());
                e.printStackTrace();
            }
        }
    }

    public static boolean runCommand(User user, MessageContext messageContext, String cmdLine) {
        int firstSpace = cmdLine.indexOf(' ');
        String argLine; String[] args;
        if(firstSpace > 0) {
            argLine = cmdLine.substring(firstSpace + 1);
            args = argLine.split(" ");
            cmdLine = cmdLine.substring(0, firstSpace);
        } else {
            argLine = "";
            args = new String[0];
        }
        System.out.println(cmdLine);
        System.out.println(argLine);
        BaseCommand baseCommand = commands.get(cmdLine.toLowerCase());
        if(baseCommand == null) return false;
        try {
            baseCommand.run(user, messageContext, args, argLine);
        } catch(Exception e) {
            baseCommand.commandError(user, messageContext, e);
        }
        return true;
    }
}
