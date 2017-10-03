package server;

import util.Contact;

import java.net.DatagramPacket;

public class ServerProcessor implements Runnable
{
    private DatagramPacket receivedPacket;
    private Server master;

    public ServerProcessor(Server master, DatagramPacket receivedPacket)
    {
        this.master = master;
        this.receivedPacket = receivedPacket;
    }

    @Override
    public void run()
    {
        byte [] receivedData = receivedPacket.getData();
        System.out.println("\nIncoming message from <"+receivedPacket.getAddress().getHostAddress()+":"+receivedPacket.getPort()+">...");
        analyze(receivedData);
    }

    private void analyze(byte [] message)
    {
        switch ((char)message[0])
        {
            case 'R':
                master.registerNewUser(receivedPacket);
                break;
            case 'F':
                byte [] sender = new byte[message[1]];
                for (int i = 0; i < message[1]; i++)
                {
                    sender[i] = message[2+i];
                }
                final String callerAlias = new String(sender);
                if (master.getUserList().stream().anyMatch(contact -> contact.getAlias().equals(callerAlias)))
                {
                    Contact caller = master.getUserList().stream().filter(contact -> contact.getAlias().equals(callerAlias)).findFirst().get();
                    System.out.println("Find user request from registered caller \""+callerAlias+"\"...");
                    byte [] temp = new byte[message[message[1]+2]];
                    for (int i = 0; i < temp.length; i++)
                    {
                        temp[i] = message[message[1]+3+i];
                    }
                    final String aliasToFind = new String(temp);
                    master.sendContactInfoMessage(aliasToFind,caller);
                }
                else
                    master.sendExceptionMessage("Caller <"+receivedPacket.getAddress().getHostAddress()+":"+receivedPacket.getPort()+"> is not registered...",receivedPacket.getAddress(),receivedPacket.getPort());
                break;
            case 'M':
                master.sendCheckMessageForAliasChange(receivedPacket);
                break;
            case 'Y':
                master.proceedConfirmResponse(receivedPacket);
                break;
            case 'K':
                master.sendCheckMessageForPublicKeyChange(receivedPacket);
                break;
        }
    }
}
