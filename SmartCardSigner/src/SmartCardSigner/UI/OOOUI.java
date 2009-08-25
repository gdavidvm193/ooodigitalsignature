package SmartCardSigner.UI;

import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;

/**
 * Classe che implementa  {@link BaseUI} per la gestione dell'interfaccia grafica in OpenOffice
 *
 * @author redbass
 */
public class OOOUI implements BaseUI
{

    protected JPasswordField passwordPin;
    protected JTextField moduleField;
    protected boolean canGetData = false;

    private JFrame frame;

    /**
     * Metodo di stampa dei mesasggi standard
     *
     * @param in testo del messaggio
     */
    public void baseMsg(String in) {
        System.out.println(in);
    }

    /**
     * Metodo di stampa dei mesasggi di status
     *
     * @param in testo del messaggio
     */
    public void statusMsg(String in) {
        System.out.println(in);
    }

    /**
     * Metodo di stampa dei messaggi informativi
     *
     * @param in testo del messaggio
     */
    public void infoMsg(String in) {
        System.out.println(in);
    }

    /**
     * Metodo di stampa dei messaggi di richieste e acquisizione informazioni
     * degli stessi, per domande mo0lto semplici.
     *
     * @param in testo del messaggio
     */
    public String selectMsg(String in)
    {
        System.out.println(in);
        return null;
    }

    /**
     * Metodo di stampa degli errori
     *
     * @param in testo del messaggio
     */
    public void errMsg(String in) {
        System.out.println(in);
    }

    /**
     * Costruttore dell'interfaccia grafica per OpenOffice
     */
    public OOOUI()
    {


    }

    public void init()
    {
        frame = new JFrame("Smartcard Signer");
        baseSets();
    }

    /**
     * Crea un'interfaccia grafica in un {@link javax.swing.JFrame} per acquisire informaizoni 
     * sul modulo PKCS11 da utilizzare e il pin della spartcard
     * 
     */
    private void baseSets()
    {
        JPanel panel;
        JLabel labelModule, labelPin;
        JButton moduleButton, button;

        Dimension frameDim = new Dimension(350,200);
        Dimension labelDim = new Dimension(50,20);
        Dimension border = new Dimension(10,10);
        Dimension dataDim = new Dimension(frameDim.width-labelDim.width-(4*border.width), labelDim.height);
        Dimension buttons = new Dimension(90,20);

        frame.setSize(frameDim);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setLocation(100, 100);
        panel = new JPanel();
        panel.setLayout( null );
        

        labelModule = new JLabel("Module");
        labelModule.setSize(labelDim);
        labelModule.setLocation(border.width, border.width);


        moduleField = new JTextField(" ");
        moduleField.setSize(dataDim);
        moduleField.setLocation(border.width*2+labelDim.width, border.height);


        labelPin = new JLabel("Pin");
        labelPin.setSize(labelDim);
        labelPin.setLocation(border.width, border.width*2+labelDim.height);

        passwordPin = new JPasswordField();
        passwordPin.setSize(dataDim);
        passwordPin.setLocation(border.width*2+labelDim.width, border.width*2+labelDim.height);

        button = new JButton("Continue");
        button.setSize(buttons);
        button.setLocation((frame.getWidth()/2)-(button.getWidth()/2), border.width*3+labelDim.height*2);
        button.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent e)
            {
                canGetData = true;
                frame.dispose();
            }
        });

        
        panel.add(labelModule);
        panel.add(moduleField);
        panel.add(labelPin);
        panel.add(passwordPin);
        panel.add(button);

        frame.add(panel);
        frame.setVisible(true);
    }

    /**
     * Retituisce un valore di tipo {@link java.lang.Boolean boolean}  che è
     * <code>true</code> se è stato premuto il bottone "continue" nell'interfaccia
     * oppure ritorna <code>false</code>
     *
     * @return {@link java.lang.Boolean boolean}: {@code false} se il pulsante dell interfacci anon è mai stato premuto, {@code true} altrimenti
     */
    public boolean canGetData()
    {
        return canGetData;
    }

    /** Restiruisce {@link java.lang.String String[]} contenente le info richieste nell'interfaccia
     *
     * @return {@link java.lang.String String[]}: {@code String[0]} contiene il path del modulo PKCS11,
     * {@code String[0]} contiene il pin
     */
    public  String[] getData()
    {
        String[] s = new String[2];
        s[0] = moduleField.getText();
        s[1] = String.valueOf(passwordPin.getPassword());
        return s;
    }
}
