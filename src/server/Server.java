package server;

import util.*;

import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Server extends Thread
{
    private DatagramSocket serverSocket;
    private KeyPair keys;

    private List<Contact> userList;
    private Cryptograher cryptograher;
    private ExecutorService executor;

    public List<Contact> getUserList()
    {
        return this.userList;
    }

    public Server(int serverPort)
    {
        try
        {
            serverSocket = new DatagramSocket(serverPort);
            System.out.println("Starting server on port "+serverSocket.getLocalPort()+"...");
        }
        catch (SocketException e) {e.printStackTrace();System.exit(-1);}
        this.cryptograher = new Cryptograher();
        this.userList = new ArrayList<>();
        this.executor = Executors.newCachedThreadPool();
        this.keys = cryptograher.generateKeyPair();
    }

    @Override
    public void run()
    {
        while (!serverSocket.isClosed())
        {
            DatagramPacket packet = new DatagramPacket(new byte[512],512);
            try
            {
                serverSocket.receive(packet);
                executor.submit(new ServerProcessor(this,packet));
            }
            catch (IOException e) {e.printStackTrace();}
        }
    }


    public void registerNewUser(DatagramPacket packet)
    {
        System.out.println("Registration request from <"+packet.getAddress().getHostAddress()+":"+packet.getPort()+">...");
        byte [] message = packet.getData();
        byte [] newUserAlias = new byte[message[1]];
        for (int i = 0; i < newUserAlias.length; i++)
        {
            newUserAlias[i] = message[2+i];
        }
        final String alias = new String(newUserAlias);
        if (userList.stream().anyMatch(contact -> contact.getAlias().equals(alias)))
        {
            System.out.println("Contact <"+alias+"> already exists in server register...");
            sendExceptionMessage("User with alias \""+alias+"\" already exist...",packet.getAddress(),packet.getPort());
            return;
        }
        try
        {
            byte [] newUserPublicKey = new byte[162];
            for (int i = 0; i < newUserPublicKey.length; i++)
            {
                newUserPublicKey[i] = message[2+message[1]+i];
            }
            PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(newUserPublicKey));
            Contact contact = new Contact(packet.getAddress(),packet.getPort(),alias,key);

            if (userList.add(contact))
            {
                System.out.println("Contact \""+contact.getAlias()+"\" <"+contact.getContactIP().getHostAddress()+":"+contact.getContactPort()+"> added to register...");
                sendAcceptMessage(contact.getAlias(),contact.getContactIP(),contact.getContactPort());
            }

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e)
        {
            e.printStackTrace();
            System.err.println("Error ocured during message encryption...");
        }
    }


    public void sendAcceptMessage(String alias,InetAddress ip,int port)
    {
        byte [] response = new byte[163];
        response[0] = (byte)'A';
        byte [] pubKey = keys.getPublic().getEncoded();
        System.arraycopy(pubKey,0,response,1,pubKey.length);
        try
        {
            serverSocket.send(new DatagramPacket(response,response.length,ip,port));
            System.out.println("Accept message sent to \""+alias+"\" <"+ip+":"+port+">...");
        }
        catch (IOException e) {System.out.println("Cannot send accept message to new registered user \""+alias+"\" <"+ip.getHostAddress()+":"+port+">:");e.printStackTrace();}
    }


    public synchronized void sendContactInfoMessage(String aliasToFind,Contact caller)
    {
        try
        {
            Contact contact = userList.stream().filter(c->c.getAlias().equals(aliasToFind)).findFirst().get();
            contact.getCallers().add(caller);
            byte [] contactAlias = contact.getAlias().getBytes();
            byte [] contactIP = contact.getContactIP().getAddress();
            byte [] contactPort = ByteBuffer.allocate(4).putInt(contact.getContactPort()).array();
            byte [] contactPublicKey = contact.getPublicKey().getEncoded();
            byte [] response = new byte[2+contactAlias.length+contactIP.length+contactPort.length+contactPublicKey.length];
            response[0] = (byte)'C';
            response[1] = (byte)contactAlias.length;
            for (int i = 0; i < contact.getAlias().length(); i++)
            {
                response[2+i] = contactAlias[i];
            }
            for (int i = 0; i < 4; i++)
            {
                response[2+contactAlias.length+i] = contactIP[i];
                response[6+contactAlias.length+i] = contactPort[i];
            }
            for (int i = 0; i < contactPublicKey.length; i++)
            {
                response[10+contactAlias.length+i] = contactPublicKey[i];
            }

            DatagramPacket packet = new DatagramPacket(response,response.length,caller.getContactIP(),caller.getContactPort());
            try
            {
                serverSocket.send(packet);
                System.out.println("Contact info of user \""+contact.getAlias()+"\" was sent to registered caller \""+caller.getAlias()+"\"...");
            }
            catch (IOException e) {e.printStackTrace();}
        } catch (NoSuchElementException e) {sendExceptionMessage("Called user \""+aliasToFind+"\" not found...",caller.getContactIP(),caller.getContactPort());}
    }


    public void sendExceptionMessage(String error,InetAddress ip,int port)
    {
        System.out.println(error);
        if (error.equals("Caller <"+ip.getHostAddress()+":"+port+"> is not registered...")) error = "Unregistered user can't call for other users' aliases...";
        byte [] exception = error.getBytes();
        byte [] response = new byte[2+exception.length];
        response[0] = (byte)'E';
        response[1] = (byte) exception.length;
        for (int i = 0; i < exception.length; i++)
        {
            response[2+i] = exception[i];
        }
        try
        {
            serverSocket.send(new DatagramPacket(response,response.length,ip,port));
            System.out.println("Sending exception response to caller <"+ip.getHostAddress()+":"+port+">...");
        }
        catch (IOException e) {e.printStackTrace();}
    }

    public void sendCheckMessageForAliasChange(DatagramPacket packet)
    {
        byte [] message = packet.getData();
        String oldCallerAlias = "",newCallerAlias = "";
        for (int i = 0; i < message[1]; i++)
        {
            oldCallerAlias+=(char)message[2+i];
        }
        final String callerAlias = oldCallerAlias;
        if (!this.userList.stream().anyMatch(c->c.getAlias().equals(callerAlias)))
        {
            sendExceptionMessage("Unregistered user can't change his alias...",packet.getAddress(),packet.getPort());
            return;
        }
        for (int i = 0; i < message[2+message[1]]; i++)
        {
            newCallerAlias+=(char)message[3+message[1]+i];
        }
        final String newAlias = newCallerAlias;
        if (!this.userList.stream().anyMatch(c->c.getAlias().equals(newAlias)))
        {

            Contact caller = this.userList.stream().filter(c->c.getAlias().equals(callerAlias)).findFirst().get();
            int idx = this.userList.indexOf(caller);
            caller.setLastCommand(message);
            caller.setPrompt(cryptograher.randomIdentifyingString(10));
            try
            {
                System.out.println("Caller \""+callerAlias+"\": "+Arrays.toString(caller.getPrompt()));
                byte [] encodedWithFirstLayer = cryptograher.encrypt(caller.getPrompt(),keys.getPrivate());
                byte [] encodedWithSecondLayer = cryptograher.encrypt(encodedWithFirstLayer,caller.getPublicKey());
                byte [] messageToSend = new byte[2+encodedWithSecondLayer.length];
                messageToSend[0] = (byte) 'Q';
                messageToSend[1] = (byte) caller.getPrompt().length;
                for (int i = 0; i < encodedWithSecondLayer.length; i++)
                {
                    messageToSend[2+i] = encodedWithSecondLayer[i];
                }
                DatagramPacket packetToSend = new DatagramPacket(messageToSend,messageToSend.length,packet.getAddress(),packet.getPort());
                serverSocket.send(packetToSend);
                System.out.println("Sending identity authentication message to \""+callerAlias+"\" <"+caller.getContactIP().getHostAddress()+":"+caller.getContactPort()+">...");
            }
            catch (Exception e) {e.printStackTrace();}
            this.userList.set(idx,caller);
        }
        else
        {
            Contact exisistingContact = this.userList.stream().filter(c->c.getAlias().equals(newAlias)).findFirst().get();
            System.out.println("Impossible to change user's old alias \""+oldCallerAlias+"\" to new alias \""+newCallerAlias+"\""+
            ": user with this alias already exists in user list -> ["+exisistingContact.getAlias()+"] <"+exisistingContact.getContactIP().getHostAddress()+
            ":"+exisistingContact.getContactPort()+"> ");
            sendExceptionMessage("User with alias \""+newCallerAlias+"\" already exist...",packet.getAddress(),packet.getPort());
        }
    }

    public void sendCheckMessageForPublicKeyChange(DatagramPacket packet)
    {
        byte [] message = packet.getData();
        String alias = "";
        for (int i = 0; i < message[1]; i++)
        {
            alias+=(char)message[2+i];
        }
        final String callerAlias = alias;
        if (!this.userList.stream().anyMatch(c->c.getAlias().equals(callerAlias)))
        {
            sendExceptionMessage("Unregistered user can't change his public key...",packet.getAddress(),packet.getPort());
            return;
        }
        Contact caller = this.userList.stream().filter(c->c.getAlias().equals(callerAlias)).findFirst().get();
        int idx = this.userList.indexOf(caller);
        caller.setLastCommand(message);
        caller.setPrompt(cryptograher.randomIdentifyingString(10));
        try
        {
            System.out.println("Caller \""+callerAlias+"\": "+Arrays.toString(caller.getPrompt()));
            byte [] encodedWithFirstLayer = cryptograher.encrypt(caller.getPrompt(),keys.getPrivate());
            byte [] encodedWithSecondLayer = cryptograher.encrypt(encodedWithFirstLayer,caller.getPublicKey());
            byte [] messageToSend = new byte[2+encodedWithSecondLayer.length];
            messageToSend[0] = (byte) 'Q';
            messageToSend[1] = (byte) caller.getPrompt().length;
            for (int i = 0; i < encodedWithSecondLayer.length; i++)
            {
                messageToSend[2+i] = encodedWithSecondLayer[i];
            }
            DatagramPacket packetToSend = new DatagramPacket(messageToSend,messageToSend.length,packet.getAddress(),packet.getPort());
            serverSocket.send(packetToSend);
            System.out.println("Sending identity authentication message to \""+callerAlias+"\" <"+caller.getContactIP().getHostAddress()+":"+caller.getContactPort()+">...");
        }
        catch (Exception e) {e.printStackTrace();}
        this.userList.set(idx,caller);
    }

    private void modifyContactAlias(Contact contact)
    {
        byte [] message = contact.getLastCommand();
        String oldAlias = "",newAlias = "";
        for (int i = 0; i < message[1]; i++)
        {
            oldAlias+=(char)message[2+i];
        }
        if (contact.getAlias().equals(oldAlias))
        {
            for (int i = 0; i < message[2+message[1]]; i++)
            {
                newAlias+=(char)message[3+message[1]+i];
            }
            contact.setAlias(newAlias);
            this.userList.set(userList.indexOf(contact),contact);
            System.out.println("User contact <"+contact.getContactIP().getHostAddress()+":"+contact.getContactPort()+"> alias \""+oldAlias+
            "\" was changed to alias \""+contact.getAlias()+"\"...");
            byte [] response = new byte[9];
            response[0] = (byte)'U';
            try
            {
                serverSocket.send(new DatagramPacket(response,response.length,contact.getContactIP(),contact.getContactPort()));
            }
            catch (IOException e) {e.printStackTrace();}
            if (!contact.getCallers().isEmpty())
            {
                System.out.println("Sending changes to user \""+contact.getAlias()+"\" callers...");
                byte [] oca = oldAlias.getBytes();
                byte [] cca = contact.getAlias().getBytes();
                byte [] changesInfo = new byte[3+oca.length+cca.length];
                changesInfo[0] = (byte)'G';
                changesInfo[1] = (byte) oca.length;
                for (int i = 0; i < changesInfo[1]; i++)
                {
                    changesInfo[2+i] = oca[i];
                }
                changesInfo[2+changesInfo[1]] = (byte) cca.length;
                for (int i = 0; i < cca.length; i++)
                {
                    changesInfo[3+changesInfo[1]+i] = cca[i];
                }
                for (Contact caller:contact.getCallers())
                {
                    try {
                        serverSocket.send(new DatagramPacket(changesInfo,changesInfo.length,caller.getContactIP(),caller.getContactPort()));
                        System.out.println("Changes of user \""+contact.getAlias()+"\" sent to caller \""+caller.getAlias()+"\" <"+caller.getContactIP().getHostAddress()+":"+caller.getContactPort()+">...");
                    } catch (IOException e) {e.printStackTrace();}
                }
            }
        }
    }

    public void proceedConfirmResponse(DatagramPacket packet)
    {
        Contact caller = this.userList.stream().filter(c->c.getContactIP().equals(packet.getAddress())&&c.getContactPort()==packet.getPort()).findFirst().get();
        System.out.println("Authentication confirm from \""+caller.getAlias()+"\" <"+caller.getContactIP().getHostAddress()+":"+caller.getContactPort()+">...");
        byte [] message = packet.getData();
        //System.out.println(caller);
        int stringIDLength = message[2+message[1]];
        if (stringIDLength == caller.getPrompt().length)
        {
            System.out.println("Prompt length is correct..");
            byte [] encryptedResponce = new byte[256];
            for (int i = 0; i < encryptedResponce.length; i++)
            {
                encryptedResponce[i] = message[3+message[1]+i];
            }
            byte [] confirm = new byte[stringIDLength];
            try
            {
                byte [] firstDecryptedLayer = cryptograher.decrypt(encryptedResponce,keys.getPrivate());
                byte [] secondDecryptedLayer = cryptograher.decrypt(firstDecryptedLayer,caller.getPublicKey());
                for (int i = 0; i < confirm.length; i++)
                {
                    confirm[i] = secondDecryptedLayer[i];
                }
                //System.out.println(Arrays.toString(confirm));
                if (Arrays.equals(caller.getPrompt(),confirm))
                {
                    System.out.println("User \""+caller.getAlias()+"\" is confirmed, perfoming last user's command...");
                    switch (caller.getLastCommand()[0])
                    {
                        case 'M':
                            modifyContactAlias(caller);
                            break;
                        case 'K':
                            modifyContactPublicKey(caller);
                            break;
                    }
                }
            }
            catch (Exception e) {e.printStackTrace();return;}
        }
        else sendExceptionMessage("Confirm response rejected...",caller.getContactIP(),caller.getContactPort());
    }

    private void modifyContactPublicKey(Contact contact)
    {
        byte [] message = contact.getLastCommand();
        //MessageInfo.messageInfo(message);
        try
        {
            String userAlias = "";
            for (int i = 0; i < message[1]; i++)
            {
                userAlias += (char) message[2 + i];
            }
            final String contactAlias = userAlias;
            byte [] newContactPublicKey = new byte[162];
            for (int i = 0; i < newContactPublicKey.length; i++)
            {
                newContactPublicKey[i] = message[2+message[1]+i];
            }
            contact.setPublicKey(KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(newContactPublicKey)));
            this.userList.set(this.userList.indexOf(contact),contact);
            System.out.println("Contact \""+contact.getAlias()+"\" public key was changed...");
            byte [] response = new byte[1];
            response[0] = (byte)'J';
            try
            {
                serverSocket.send(new DatagramPacket(response,response.length,contact.getContactIP(),contact.getContactPort()));
            }
            catch (IOException e) {e.printStackTrace();}
            if (!contact.getCallers().isEmpty())
            {
                byte [] alias = contact.getAlias().getBytes();
                byte [] newPublicKey = contact.getPublicKey().getEncoded();
                byte [] changesInfo = new byte[2+alias.length+newPublicKey.length];
                changesInfo[0] = (byte)'O';
                changesInfo[1] = (byte)alias.length;
                for (int i = 0; i < changesInfo[1]; i++)
                {
                    changesInfo[2+i] = alias[i];
                }
                for (int i = 0; i < newPublicKey.length; i++)
                {
                    changesInfo[2+changesInfo[1]+i] = newPublicKey[i];
                }
                for (Contact caller:contact.getCallers())
                {
                    try
                    {
                        serverSocket.send(new DatagramPacket(changesInfo,changesInfo.length,caller.getContactIP(),caller.getContactPort()));
                        System.out.println("Public key changes of user \""+contact.getAlias()+"\" sent to caller \""+caller.getAlias()+"\" <"+caller.getContactIP().getHostAddress()+":"+caller.getContactPort()+">...");
                    }
                    catch (IOException e) {e.printStackTrace();}
                }
            }

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {e.printStackTrace();}
    }

    public static void main(String[] args)
    {
        new Server(1234).start();
    }
}
