package me.draconia.chat.server;

import me.draconia.chat.types.User;
import me.draconia.chat.types.UserFactory;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.HashMap;

public class ServerUserFactory extends UserFactory {
    private final HashMap<String, User> userMap;

    private Thread saverThread = null;
    private boolean runSaving = true;

    public ServerUserFactory() {
        HashMap<String, User> loadedMap = null;
        try {
            ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream("users.dat"));
            loadedMap = (HashMap<String, User>)objectInputStream.readObject();
            objectInputStream.close();
        } catch(Exception e) {
            e.printStackTrace();
        }
        if(loadedMap == null) {
            userMap = new HashMap<String, User>();
        } else {
            userMap = loadedMap;
        }

        Runtime.getRuntime().addShutdownHook(new Thread() {
            @Override
            public void run() {
                runSaving = false;
                try {
                    saverThread.join();
                } catch(InterruptedException e) { }
                save();
            }
        });

        saverThread = new Thread() {
            @Override
            public void run() {
                while(runSaving) {
                    try {
                        Thread.sleep(10000);
                    } catch (InterruptedException e) { }
                    save();
                }
            }
        };
        saverThread.start();
    }

    public void save() {
        try {
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(new FileOutputStream("users.dat"));
            synchronized (userMap) {
                objectOutputStream.writeObject(userMap);
            }
            objectOutputStream.close();
        } catch(Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    protected User createFromLogin(String login) {
        synchronized (userMap) {
            User ret = userMap.get(login);
            if(ret != null)
                return ret;
            ret = new ServerUser(login);
            ret.setNickname(login);
            userMap.put(login, ret);
            return ret;
        }
    }
}
