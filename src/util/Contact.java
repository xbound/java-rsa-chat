package util;

import java.io.Serializable;
import java.net.InetAddress;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Contact implements Serializable
{
    private String alias;
    private InetAddress contactIP;
    private int contactPort;
    private PublicKey publicKey;

    private StringBuffer buffer;
    private List<Contact> callers = new ArrayList<>();
    private byte [] prompt;
    private byte [] lastCommand;
    
    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    public InetAddress getContactIP() {
        return contactIP;
    }

    public void setContactIP(InetAddress contactIP) {
        this.contactIP = contactIP;
    }

    public int getContactPort() {
        return contactPort;
    }

    public void setContactPort(int contactPort) {
        this.contactPort = contactPort;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public byte[] getPrompt() {
        return prompt;
    }

    public void setPrompt(byte[] prompt) {
        this.prompt = prompt;
    }

    public byte[] getLastCommand() {
        return lastCommand;
    }

    public void setLastCommand(byte[] lastCommand) {
        this.lastCommand = lastCommand;
    }

    public List<Contact> getCallers() {
        return callers;
    }

    public void setCallers(List<Contact> callers) {
        this.callers = callers;
    }

    public StringBuffer getBuffer() {
        return buffer;
    }

    public void setBuffer(StringBuffer buffer) {
        this.buffer = buffer;
    }

    public Contact(InetAddress contactIp, int contactPort, String alias, PublicKey publicKey)
    {
        this.contactIP = contactIp;
        this.contactPort = contactPort;
        this.alias = alias;
        this.publicKey = publicKey;
        this.prompt = null;
        this.lastCommand = null;
        this.buffer = new StringBuffer();
    }

    public Contact(InetAddress contactIP, int contactPort, String alias)
    {

        setAlias(alias);
        setPrompt(null);
        setLastCommand(null);
        setBuffer(new StringBuffer());
    }

    public Contact(InetAddress contactIP, int contactPort, PublicKey key)
    {
        setContactIP(contactIP);
        setContactPort(contactPort);
        setPublicKey(key);
        setPrompt(null);
        setBuffer(new StringBuffer());
    }

    @Override
    public String toString()
    {
        return  (alias != null?"Alias: "+alias:"")+
                "\nIP: "+ contactIP.getHostAddress()+
                "\nPORT: "+ contactPort +
                "\nPublic key: "+(publicKey!=null?"+":"-")+
                (lastCommand!=null?"\nLast command: "+ Arrays.toString(lastCommand):"")+
                (prompt!=null?"\nPrompt: "+Arrays.toString(prompt):"");
    }
}