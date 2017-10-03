package client.model;

import client.controller.GUIController;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import util.*;

import java.io.IOException;
import java.io.Serializable;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class User extends Thread implements Serializable
{
    private DatagramSocket socket;
    private String userAlias;
    private KeyPair keys;
    private byte [] byteBuffor;
    private byte[] privateKeyBuffer;
    private byte[] publicKeyBuffer;
    private ObservableList<Contact> contactList;
    private List<Contact> serverList;
    private Cryptograher cryptograher;
    private ExecutorService executor;

    private GUIController controller;

    public User(String alias, GUIController controller)
    {
        this.userAlias = alias;
        this.cryptograher = new Cryptograher();
        this.contactList = FXCollections.observableList(new ArrayList<Contact>());
        this.serverList = new ArrayList<>();
        this.keys = cryptograher.generateKeyPair();
        this.executor = Executors.newCachedThreadPool();
        this.controller = controller;
        if (this.controller != null) controller.usernameLabel.setText(this.userAlias);
        try
        {
            this.socket = new DatagramSocket();
            System.out.println("Starting user \""+alias+"\" on port "+socket.getLocalPort()+"...");
            if (controller != null) controller.showMessageDialog("User created successfully!","Starting user \""+alias+"\" on port "+socket.getLocalPort()+"...");
        }
        catch (SocketException e)
        {
            System.out.println("Cannot open user socket: "+e.getMessage());
            if (controller != null) controller.showMessageDialog("Error!","Error occured, please try later!");
        }
    }

    public GUIController getController()
    {
        return controller;
    }

    public ObservableList<Contact> getContactList()
    {
        return this.contactList;
    }

    public List<Contact> getServerList()
    {
        return serverList;
    }

    @Override
    public void run()
    {
        while (!socket.isClosed())
        {
            DatagramPacket receivedPacket = new DatagramPacket(new byte[512],512);
            try
            {
                socket.receive(receivedPacket);
                executor.submit(new UserProcessor(this,receivedPacket));
            }
            catch (IOException e) {e.printStackTrace();}
        }
    }

    public synchronized void sendRegisterRequest(InetAddress serverIP, int serverPort)
    {
        byte [] userAlias = this.userAlias.getBytes();
        byte [] pubKey = keys.getPublic().getEncoded();
        byte [] message = new byte[userAlias.length+pubKey.length+2];
        message[0] = (byte) 'R';
        message[1] = (byte) userAlias.length;
        for (int i = 0; i < message[1]; i++)
        {
            message[2+i] = userAlias[i];
        }
        for (int i = 0; i < pubKey.length; i++)
        {
            message[2+userAlias.length+i] = pubKey[i];
        }
        //MessageInfo.messageInfo(message);
        DatagramPacket packet = new DatagramPacket(message,message.length,serverIP,serverPort);
        try
        {
            socket.send(packet);
            System.out.println("Sending registration request to server <"+serverIP.getHostAddress()+":"+serverPort+">...");
        }
        catch (IOException e) {e.printStackTrace();}
    }

    public void getContactFromServer(String contactAlias,InetAddress serverIP,int serverPort)
    {
        byte [] aliasToFind = contactAlias.getBytes();
        byte [] callerAlias = this.userAlias.getBytes();
        byte [] message = new byte[3+aliasToFind.length+callerAlias.length];
        message[0] = (byte)'F';
        message[1] = (byte)callerAlias.length;
        for (int i = 0; i < callerAlias.length; i++)
        {
            message[2+i] = callerAlias[i];
        }
        message[callerAlias.length+2] = (byte) aliasToFind.length;
        for (int i = 0; i < aliasToFind.length; i++)
        {
            message[callerAlias.length+3+i] = aliasToFind[i];
        }
        DatagramPacket packet = new DatagramPacket(message,message.length,serverIP,serverPort);
        try
        {
            socket.send(packet);
            System.out.println("\nRequest to find ip and port of user with alias \""+new String(aliasToFind)+"\" was sent to server <"+ serverIP.getHostAddress()+":"+serverPort+">...");
        }
        catch (IOException e) {e.printStackTrace();}
    }

    public void addNewServerContact(byte [] message, InetAddress newServerIP, int newServerPort)
    {
        byte [] newServerPublicKey = new byte[162];
        for (int i = 0; i < 162; i++)
        {
            newServerPublicKey[i] = message[1+i];
        }
        try
        {
            PublicKey newServerPK = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(newServerPublicKey));
            Contact newServer = new Contact(newServerIP,newServerPort,newServerPK);
            if (serverList.add(newServer))
            {
                System.out.println("New server <"+newServer.getContactIP().getHostAddress()+":"+newServer.getContactPort()+"> was added to server list...");
                if (controller != null) controller.showMessageDialog("You're connected...","New server "+newServer.getContactIP().getHostAddress()+":"+newServer.getContactPort()+" added");
            }
        }
        catch (InvalidKeySpecException | NoSuchAlgorithmException e) {e.printStackTrace();}
    }

    public synchronized void addNewUserContact(byte [] message)
    {
        String alias = "";
        for (int i = 0; i < message[1]; i++)
        {
            alias +=(char)message[2+i];
        }
        byte [] port = new byte[4],ip = new byte[4];
        for (int i = 0; i < 4; i++)
        {
            ip[i] = message[message[1]+2+i];
            port[i] = message[message[1]+6+i];
        }
        byte [] contactPublicKey = new byte[162];
        for (int i = 0; i < contactPublicKey.length; i++)
        {
            contactPublicKey[i] = message[10+message[1]+i];
        }
        try
        {
            InetAddress contactIP = InetAddress.getByAddress(ip);
            int contactPort = ByteBuffer.wrap(port,0,port.length).getInt();
            PublicKey contactPK = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(contactPublicKey));
            Contact newContact = new Contact(contactIP,contactPort,alias,contactPK);
            if (contactList.add(newContact)) System.out.println("New user \""+newContact.getAlias()+"\" <"+newContact.getContactIP().getHostAddress() +":"+newContact.getContactPort()+"> was added to contact list...");
        }
        catch (UnknownHostException | NoSuchAlgorithmException | InvalidKeySpecException e) {e.printStackTrace();}
    }

    public void handleExceptionResponce(byte [] message,InetAddress serverIP,int serverPort)
    {
        System.out.print("Exception received from server <"+serverIP.getHostAddress()+":"+serverPort+">: ");
        String exception = "";
        for (int i = 0; i < message[1]; i++)
        {
            exception+=(char)message[2+i];
        }
        System.out.println(exception);
        if (controller != null) controller.showMessageDialog("Warning!", exception);
    }

    public synchronized void authenticationResponse(DatagramPacket packet)
    {
        Contact serverCaller = this.serverList.stream().filter(c->c.getContactIP().equals(packet.getAddress())&&c.getContactPort()==packet.getPort()).findFirst().get();
        System.out.println("Authentication checking from <"+serverCaller.getContactIP().getHostAddress()+":"+serverCaller.getContactPort()+">...");
        //System.out.println(serverCaller);
        byte [] message = packet.getData();
        byte [] encryptedMessage = new byte[256];
        for (int i = 0; i < 256; i++)
        {
            encryptedMessage[i] = message[2+i];
        }
        try
        {
            byte [] firstLayer = cryptograher.decrypt(encryptedMessage,keys.getPrivate());
            byte [] secondLayer = cryptograher.decrypt(firstLayer,serverCaller.getPublicKey());
            byte [] decryptedMessage = new byte[message[1]];
            for (int i = 0; i < decryptedMessage.length; i++)
            {
                decryptedMessage[i] = secondLayer[i];
            }
            System.out.println("Decrypted message from <"+serverCaller.getContactIP().getHostAddress()+":"+serverCaller.getContactPort()+">: "+Arrays.toString(decryptedMessage));
            byte [] firstEncryptedLayer = cryptograher.encrypt(decryptedMessage,keys.getPrivate());
            byte [] secondEncryptedLayer = cryptograher.encrypt(firstEncryptedLayer,serverCaller.getPublicKey());
            //System.out.println(Arrays.toString(secondEncryptedLayer));
            byte [] alias = userAlias.getBytes();
            byte [] encryptedResponse = new byte[3+alias.length+secondEncryptedLayer.length];
            encryptedResponse[0] = (byte)'Y';
            encryptedResponse[1] = (byte) userAlias.length();
            for (int i = 0; i < userAlias.length(); i++)
            {
                encryptedResponse[2+i] = alias[i];
            }
            encryptedResponse[2+encryptedResponse[1]] = (byte) decryptedMessage.length;
            for (int i = 0; i < secondEncryptedLayer.length; i++)
            {
                encryptedResponse[3+encryptedResponse[1]+i] = secondEncryptedLayer[i];
            }
            //MessageInfo.messageInfo(encryptedResponse);
            DatagramPacket response = new DatagramPacket(encryptedResponse,encryptedResponse.length,serverCaller.getContactIP(),serverCaller.getContactPort());
            socket.send(response);
            System.out.println("Authentication confirm response sent to <"+serverCaller.getContactIP().getHostAddress()+":"+serverCaller.getContactPort()+">...");
        }
        catch (Exception e) {e.printStackTrace();}
    }

    public synchronized void sendModifyAliasRequest(String alias)
    {
        byte [] oldAlias = this.userAlias.getBytes();
        this.byteBuffor = alias.getBytes();
        if (!serverList.isEmpty())
        {
            byte [] modifyMessage = new byte[3+oldAlias.length+byteBuffor.length];
            modifyMessage[0] = (byte)'M';
            modifyMessage[1] = (byte) oldAlias.length;
            for (int i = 0; i < oldAlias.length; i++)
            {
                modifyMessage[2+i] = oldAlias[i];
            }
            modifyMessage[oldAlias.length+2] = (byte) byteBuffor.length;
            for (int i = 0; i < byteBuffor.length; i++)
            {
                modifyMessage[oldAlias.length+3+i] = byteBuffor[i];
            }
            //MessageInfo.messageInfo(modifyMessage);
            for (Contact server:serverList)
            {
                DatagramPacket modifyRequest = new DatagramPacket(modifyMessage,modifyMessage.length,server.getContactIP(),server.getContactPort());
                try
                {
                    socket.send(modifyRequest);
                    System.out.println("\nModify message was sent to server <"+server.getContactIP().getHostAddress()+":"+server.getContactPort()+">...");
                }
                catch (IOException e) {e.printStackTrace();}
            }
        }
        else modifyAliasFromBuffer();
    }

    public void modifyAlias(InetAddress serverIP, int serverPort)
    {
        System.out.println("Alias modifying was approved...");
        if (this.serverList.stream().anyMatch(c->c.getContactIP().equals(serverIP)&&c.getContactPort()==serverPort))
        {
            modifyAliasFromBuffer();
        }
        else System.out.println("Unknown caller/server skipped...");
    }

    private void modifyAliasFromBuffer()
    {
        String oldAlias = this.userAlias;
        this.userAlias = new String(byteBuffor);
        System.out.println("User alias \""+oldAlias+"\" was changed to \""+this.userAlias+"\"...");
        if (controller != null) controller.usernameLabel.setText(this.userAlias);
    }

    public void sendModifyPublicKeyRequest()
    {
        KeyPair newKeyPair = cryptograher.generateKeyPair();
        this.publicKeyBuffer = newKeyPair.getPublic().getEncoded();
        this.privateKeyBuffer = newKeyPair.getPrivate().getEncoded();
        if (!serverList.isEmpty())
        {
            byte [] userAlias = this.userAlias.getBytes();
            byte [] newPubKey = publicKeyBuffer;
            byte [] message = new byte[userAlias.length+newPubKey.length+2];
            message[0] = (byte) 'K';
            message[1] = (byte) userAlias.length;
            for (int i = 0; i < message[1]; i++)
            {
                message[2+i] = userAlias[i];
            }
            for (int i = 0; i < newPubKey.length; i++)
            {
                message[2+userAlias.length+i] = newPubKey[i];
            }
            //MessageInfo.messageInfo(message);
            for (Contact server:serverList)
            {
                DatagramPacket packet = new DatagramPacket(message,message.length,server.getContactIP(),server.getContactPort());
                try
                {
                    socket.send(packet);
                    System.out.println("Modify public key request was sent to server <"+server.getContactIP().getHostAddress()+":"+server.getContactPort()+">...");
                }
                catch (IOException e) {e.printStackTrace();}
            }
        }
        else modifyPublicKeyPairFromBuffer();
    }

    public String modifyPublicKey(InetAddress serverIP,int serverPort)
    {
        System.out.println("Public key modifying was approved...");
        if (this.serverList.stream().anyMatch(c->c.getContactIP().equals(serverIP)&&c.getContactPort()==serverPort))
        {
            return modifyPublicKeyPairFromBuffer();
        }
        else System.out.println("Unknown caller/server skipped...");
        return null;
    }

    private String modifyPublicKeyPairFromBuffer()
    {
        try
        {
            PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBuffer));
            PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateKeyBuffer));
            this.keys = new KeyPair(publicKey,privateKey);
            System.out.println("Key pair was changed..");
            return "Key pair was changed...";
        }
        catch (InvalidKeySpecException | NoSuchAlgorithmException e) {e.printStackTrace();}
        return null;
    }

    public void findContactAndChangeAlias(DatagramPacket packet)
    {
        if (this.serverList.stream().anyMatch(c->c.getContactIP().equals(packet.getAddress())&&c.getContactPort()==packet.getPort()))
        {
            byte [] message = packet.getData();
            int oldContactAliasLength = message[1];
            int newContactAliasLength = message[2+oldContactAliasLength];
            byte [] oldContactAlias = new byte[oldContactAliasLength],newContactAlias = new byte[newContactAliasLength];
            for (int i = 0; i < oldContactAliasLength; i++)
            {
                oldContactAlias[i] = message[2+i];
            }
            final String alias = new String(oldContactAlias);
            Contact contact = this.contactList.stream().filter(c->c.getAlias().equals(alias)).findFirst().get();
            for (int i = 0; i < newContactAliasLength; i++)
            {
                newContactAlias[i] = message[3+message[1]+i];
            }
            contact.setAlias(new String(newContactAlias));
            this.contactList.set(contactList.indexOf(contact),contact);
            System.out.println("User contact <"+contact.getContactIP().getHostAddress()+":"+contact.getContactPort()+"> alias \""+alias+ "\" was changed to alias \""+contact.getAlias()+"\"...");
        }
        else System.out.println("Unknown caller/server skipped...");
    }

    public void findContactAndChangePublicKey(DatagramPacket packet)
    {
        if (this.serverList.stream().anyMatch(c->c.getContactIP().equals(packet.getAddress())&&c.getContactPort()==packet.getPort()))
        {
            byte [] message = packet.getData();
            String alias = "";
            for (int i = 0; i < message[1]; i++)
            {
                alias += (char) message[2 + i];
            }
            final String contactAlias = alias;
            Contact contact = this.contactList.stream().filter(c->c.getAlias().equals(contactAlias)).findFirst().get();
            byte [] newContactPublicKey = new byte[162];
            for (int i = 0; i < newContactPublicKey.length; i++)
            {
                newContactPublicKey[i] = message[2+message[1]+i];
            }
            try
            {
                contact.setPublicKey(KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(newContactPublicKey)));
                this.contactList.set(this.contactList.indexOf(contact),contact);
                System.out.println("User contact \""+contact.getAlias()+"\" <"+contact.getContactIP().getHostAddress()+":"+contact.getContactPort()+"> public key was changed...");
            }
            catch (InvalidKeySpecException | NoSuchAlgorithmException e) {e.printStackTrace();}
        }
        else System.out.println("Unknown caller/server skipped...");
    }

    public void sendMessageTo(Contact contact,String messageToSend)
    {
        System.out.println("Sending message \""+messageToSend+"\" to \""+contact.getAlias()+"\" <"+contact.getContactIP().getHostAddress()+":"+contact.getContactPort()+">...");
        byte [] senderAlias = userAlias.getBytes();
        int senderAliasLength = senderAlias.length;
        byte [] encryptedMessage;
        try
        {
            encryptedMessage = cryptograher.encrypt(messageToSend.getBytes(),contact.getPublicKey());
        }
        catch (Exception e)
        {
            e.printStackTrace();
            if (controller != null) controller.showMessageDialog("Error!","Message was't sent due to error: "+e.getMessage());
            return;
        }
        byte [] message = new byte[2+senderAliasLength+encryptedMessage.length];
        message[0] = (byte)'P';
        message[1] = (byte)senderAliasLength;
        for (int i = 0; i < senderAliasLength; i++)
        {
            message[2+i] = senderAlias[i];
        }
        for (int i = 0; i < encryptedMessage.length; i++)
        {
            message[2+senderAliasLength+i] = encryptedMessage[i];
        }
        //MessageInfo.messageInfo(message);
        DatagramPacket packet = new DatagramPacket(message,message.length,contact.getContactIP(),contact.getContactPort());
        try
        {
            socket.send(packet);
            System.out.println("Message \""+messageToSend+"\" wa sent to user \""+contact.getAlias()+"\" <"+contact.getContactIP().getHostAddress()+":"+contact.getContactPort()+">...");
        }
        catch (IOException e)
        {
            e.printStackTrace();
            if (controller != null) controller.showMessageDialog("Error!","Message was't sent due to error: "+e.getMessage());
            return;
        }
        if (controller != null)
        {
            controller.chatArea.appendText("[You]: "+messageToSend+"\n");
            contact.getBuffer().append("[You]: ").append(messageToSend).append("\n");
        }
    }

    public void proceedUserMessage(DatagramPacket packet)
    {
        byte [] message = packet.getData();
        String alias = "";
        for (int i = 0; i < message[1]; i++)
        {
            alias+=(char)message[2+i];
        }
        final String senderAlias = alias;
        InetAddress senderIP = packet.getAddress();
        int senderPort = packet.getPort();
        if (this.contactList.stream().anyMatch(c->c.getAlias().equals(senderAlias)&&c.getContactIP().equals(senderIP)&&c.getContactPort()==senderPort))
        {
            Contact contact = this.contactList.stream().filter(c->c.getAlias().equals(senderAlias)&&c.getContactIP().equals(senderIP)&&c.getContactPort()==senderPort).findFirst().get();
            byte [] encryptedMessage = new byte[128];
            System.out.println("Encrypted message length: "+encryptedMessage.length);
            for (int i = 0; i < encryptedMessage.length; i++)
            {
                encryptedMessage[i] = message[2+message[1]+i];
            }
            try
            {
                byte [] decryptedMessageBytes = cryptograher.decrypt(encryptedMessage,keys.getPrivate());
                String decryptedMessage = new String(decryptedMessageBytes);
                int pos = decryptedMessage.indexOf(0);
                decryptedMessage = pos == -1 ? decryptedMessage : decryptedMessage.substring(0, pos);
                System.out.println("Message from \""+senderAlias+"\" <"+senderIP.getHostAddress()+":"+senderPort+">: "+decryptedMessage);
                if (controller != null)
                {
                    controller.chatArea.appendText("["+senderAlias+"]: "+decryptedMessage+"\n");
                    contact.getBuffer().append("[").append(senderAlias).append("]: ").append(decryptedMessage).append("\n");
                }
            } catch (Exception e)
            {
                e.printStackTrace();
                if (controller != null) controller.chatArea.appendText("Error! while decrypting message...\n");
            }
        }
        else System.out.println("Unknown user \""+senderAlias+"\" <"+senderIP.getHostAddress()+":"+senderPort+">...");
    }
}
