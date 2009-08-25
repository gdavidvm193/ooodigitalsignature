package SmartCardSigner.UI;

/**
 * Classe, da implementare, che rappresenta il sistema di visualizazione delle informazioni
 * attraverso linea di comando
 *
 * @author redbass
 */
public class StandardOutput implements BaseUI
{
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
     * degli stessi
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
}
