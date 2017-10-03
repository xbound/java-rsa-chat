package client.model;

import java.net.DatagramPacket;

public class UserProcessor implements Runnable {
    private User master;
    private DatagramPacket receivedPacket;

    public UserProcessor(User master, DatagramPacket receivedPacket)
    {
        this.master = master;
        this.receivedPacket = receivedPacket;
    }

    @Override
    public void run()
    {
        byte[] receivedData = receivedPacket.getData();
        System.out.println("\nIncoming message from <" + receivedPacket.getAddress().getHostAddress() + ":" + receivedPacket.getPort() + ">...");
        analyze(receivedData);
    }

    private synchronized void analyze(byte[] message)
    {
        switch ((char) message[0])
        {
            case 'A':
                master.addNewServerContact(message, receivedPacket.getAddress(), receivedPacket.getPort());
                break;
            case 'C':
                master.addNewUserContact(message);
                break;
            case 'E':
                master.handleExceptionResponce(message, receivedPacket.getAddress(), receivedPacket.getPort());
                break;
            case 'Q':
                master.authenticationResponse(receivedPacket);
                break;
            case 'U':
                master.modifyAlias(receivedPacket.getAddress(), receivedPacket.getPort());
                break;
            case 'G':
                master.findContactAndChangeAlias(receivedPacket);
                break;
            case 'J':
                master.modifyPublicKey(receivedPacket.getAddress(), receivedPacket.getPort());
                break;
            case 'O':
                master.findContactAndChangePublicKey(receivedPacket);
                break;
            case 'P':
                master.proceedUserMessage(receivedPacket);
                break;
        }
    }
}
