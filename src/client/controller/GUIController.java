package client.controller;

import com.jfoenix.controls.*;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.ListCell;
import javafx.scene.control.ListView;
import javafx.scene.control.SelectionMode;
import javafx.scene.input.KeyCode;
import javafx.scene.layout.StackPane;
import javafx.scene.text.Text;
import client.model.User;
import util.Contact;

import java.net.InetAddress;
import java.net.URL;
import java.util.ResourceBundle;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class GUIController implements Initializable
{
    private User user;
    private ExecutorService executorService = Executors.newSingleThreadExecutor();

    @FXML
    public JFXTextArea chatArea;

    @FXML
    public JFXTextField messageField;

    @FXML
    public Text usernameLabel;

    @FXML
    public ListView<Contact> contactListView;
    @FXML
    public JFXButton newAliasButton;

    @FXML
    public JFXButton registerButton;

    @FXML
    public StackPane mainPane;

    @FXML
    public JFXButton findUserButton;

    @FXML
    public JFXButton newKeyButton;

    @FXML
    public JFXButton sendButton;

    @FXML
    void registerPressed(ActionEvent event)
    {
        JFXDialogLayout layout = new JFXDialogLayout();
        JFXDialog dialog = new JFXDialog(mainPane,layout, JFXDialog.DialogTransition.CENTER);
        JFXButton button = new JFXButton("OK");
        if (user != null)
        {
            layout.setHeading(new Text("Enter server ip and port: "));
            JFXTextField inputField = new JFXTextField();
            inputField.setPromptText("<ip_address>:<port> Example: 127.0.0.1:2000");
            inputField.setOnKeyPressed(e ->
            {
                if (e.getCode() == KeyCode.ENTER)
                {
                    try
                    {
                        String address = inputField.getText().replaceAll("\\n","");
                        String [] s = address.split("\\:");
                        InetAddress ip = InetAddress.getByName(s[0]);
                        int port = Integer.parseInt(s[1]);
                        user.sendRegisterRequest(ip,port);
                        dialog.close();
                    }
                    catch (Exception ex) {inputField.setText("");}
                }
            });
            button.setOnAction(event1 ->
            {
                try
                {
                    String address = inputField.getText().replaceAll("\\n","");
                    String [] s = address.split("\\:");
                    InetAddress ip = InetAddress.getByName(s[0]);
                    int port = Integer.parseInt(s[1]);
                    user.sendRegisterRequest(ip,port);
                    dialog.close();
                }
                catch (Exception ex) {inputField.setText("");}
            });
            layout.getBody().add(inputField);
        }
        else
        {
            layout.setHeading(new Text("Warning!"));
            button.setOnAction(a->dialog.close());
            layout.getBody().add(new Text("Please create your user first..."));
        }
        layout.setActions(button);
        dialog.show();
    }

    @FXML
    void findUserPressed(ActionEvent event)
    {
        JFXDialogLayout layout = new JFXDialogLayout();
        layout.setHeading(new Text("Enter user's alias: "));
        JFXDialog dialog = new JFXDialog(mainPane, layout, JFXDialog.DialogTransition.CENTER);
        JFXTextField inputField = new JFXTextField();
        JFXButton button = new JFXButton("OK");
        inputField.setOnKeyPressed(e ->
        {
            if (e.getCode() == KeyCode.ENTER)
            {
                try
                {
                    if (!inputField.getText().equals(""))
                    {
                        String usname = inputField.getText().replaceAll("\\n", "");
                        for (Contact server : user.getServerList()) user.getContactFromServer(usname, server.getContactIP(), server.getContactPort());
                        dialog.close();
                    }
                    else inputField.setPromptText("Please input user's alias...");
                }
                catch (Exception ex){
                    showMessageDialog("Warning!","Create user first...");}
            }
        });
        button.setOnAction(event1 ->
        {
            try
            {
                if (!inputField.getText().equals(""))
                {
                    String usname = inputField.getText().replaceAll("\\n", "");
                    for (Contact server : user.getServerList())
                        user.getContactFromServer(usname, server.getContactIP(), server.getContactPort());
                    dialog.close();
                }
                else inputField.setPromptText("Please input user's alias...");
            }
            catch (Exception e){
                showMessageDialog("Warning!","Create user first...");}

        });
        layout.getBody().add(inputField);
        layout.setActions(button);
        dialog.show();
    }

    @FXML
    void newAliasPressed(ActionEvent event)
    {
        JFXDialogLayout layout = new JFXDialogLayout();
        layout.setHeading(new Text("New user: "));
        JFXDialog dialog = new JFXDialog(mainPane,layout, JFXDialog.DialogTransition.CENTER);
        JFXTextField inputField = new JFXTextField();
        JFXButton button = new JFXButton("OK");
        inputField.setOnKeyPressed(e ->
        {
            if (e.getCode() == KeyCode.ENTER)
            {
                if (!inputField.getText().equals(""))
                {
                    String usname = inputField.getText().replaceAll("\\n","");
                    if (user == null)
                    {

                        this.user = new User(usname,this);
                        contactListView.setItems(this.user.getContactList());
                        executorService.submit(user);
                        this.newAliasButton.setText("Change alias");
                    }
                    else user.sendModifyAliasRequest(usname);
                    dialog.close();
                }
                else inputField.setPromptText("Please input your new nickname...");
            }
        });
        button.setOnAction(event1 ->
        {
            if (!inputField.getText().equals(""))
            {
                String usname = inputField.getText().replaceAll("\\n","");
                if (user == null)
                {

                    this.user = new User(usname,this);
                    contactListView.setItems(this.user.getContactList());
                    executorService.submit(user);
                    this.newAliasButton.setText("Change alias");
                }
                else user.sendModifyAliasRequest(usname);
                dialog.close();
            }
            else inputField.setPromptText("Please input your new nickname...");
        });
        layout.getBody().add(inputField);
        layout.setActions(button);
        dialog.show();
    }

    @FXML
    void newKeyPressed(ActionEvent event)
    {
        if(user != null) for (Contact server:user.getServerList()) user.sendModifyPublicKeyRequest();
        else showMessageDialog("Warning!","Please create user and register on server first...");
    }

    @FXML
    void sendButton(ActionEvent event)
    {
        if(user != null)
        {
            Contact selectedContact = contactListView.getSelectionModel().getSelectedItem();
            if (selectedContact != null)
            {
                if (!messageField.getText().equals(""))
                    user.sendMessageTo(selectedContact,messageField.getText());
            }
        }
        else showMessageDialog("Warning!","Create user and register on server...");
    }

    public void showMessageDialog(String headerString, String message)
    {

        JFXDialogLayout layout = new JFXDialogLayout();
        layout.setHeading(new Text(headerString));
        JFXDialog dialog = new JFXDialog(mainPane,layout, JFXDialog.DialogTransition.CENTER);
        JFXButton button = new JFXButton("OK");
        button.setOnAction(a->dialog.close());
        layout.setActions(button);
        layout.getBody().add(new Text(message));
        dialog.show();
    }

    @Override
    public void initialize(URL location, ResourceBundle resources)
    {
        assert chatArea != null : "fx:id=\"chatArea\" was not injected: check your FXML file 'gui.fxml'.";
        assert messageField != null : "fx:id=\"messageField\" was not injected: check your FXML file 'gui.fxml'.";        assert contactListView != null : "fx:id=\"contactListView\" was not injected: check your FXML file 'gui.fxml'.";
        assert newAliasButton != null : "fx:id=\"newAliasButton\" was not injected: check your FXML file 'gui.fxml'.";
        assert registerButton != null : "fx:id=\"registerButton\" was not injected: check your FXML file 'gui.fxml'.";
        assert usernameLabel != null : "fx:id=\"usernameLabel\" was not injected: check your FXML file 'gui.fxml'.";
        assert mainPane != null : "fx:id=\"mainPane\" was not injected: check your FXML file 'gui.fxml'.";
        assert findUserButton != null : "fx:id=\"findUserButton\" was not injected: check your FXML file 'gui.fxml'.";
        assert newKeyButton != null : "fx:id=\"newKeyButton\" was not injected: check your FXML file 'gui.fxml'.";
        assert sendButton != null : "fx:id=\"sendButton\" was not injected: check your FXML file 'gui.fxml'.";
        contactListView.getSelectionModel().setSelectionMode(SelectionMode.SINGLE);
        contactListView.setCellFactory(param -> new ListCell<Contact>()
        {
            @Override
            protected void updateItem(Contact item, boolean empty)
            {
                super.updateItem(item, empty);
                if (item != null) setText(item.getAlias());
            }

        });
        contactListView.setOnMouseClicked(event ->
        {
            Contact selected = contactListView.getSelectionModel().getSelectedItem();
            if (selected != null)
            {
                chatArea.setText(selected.getBuffer().toString());
            }
        });
    }
}
