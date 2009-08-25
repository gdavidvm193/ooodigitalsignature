/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package SmartCardSigner;

import SmartCardSigner.UI.BaseUI;
import SmartCardSigner.UI.StandardOutput;
import iaik.pkcs.pkcs11.wrapper.CK_ATTRIBUTE;
import iaik.pkcs.pkcs11.wrapper.CK_INFO;
import iaik.pkcs.pkcs11.wrapper.CK_MECHANISM;
import iaik.pkcs.pkcs11.wrapper.CK_MECHANISM_INFO;
import iaik.pkcs.pkcs11.wrapper.CK_SLOT_INFO;
import iaik.pkcs.pkcs11.wrapper.CK_TOKEN_INFO;
import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11Connector;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;
import iaik.pkcs.pkcs11.wrapper.PKCS11;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 *
 * @author redbass
 */
public class SmartCardSigner
{
    private BaseUI ui;

    protected String pkcs11Module;  //Path of pkcs11 module
    protected PKCS11 myPKCS11Module_; //PKCS11 module loaded from pkcs11Module path
    protected long session_; // The Session open in the execution
    protected long signatureKeyHandle_;
    protected long certificateHandle_;
    protected byte[] derEncodedCertificate_;
    protected String file_;
    protected CK_MECHANISM signatureMechanism_;
    protected CK_MECHANISM digestMechanism_;
    protected MessageDigest messageDigest_;
    protected byte[] signature_;
    protected byte[] digest_;

    protected String BASE_DIR = "";
    protected String CERTIFICATE_FILE = "certificate.cer";
    protected String SIGNATURE_FILE = "signature.sig";
    protected String DIGEST_FILE = "digest.dig";

    protected long token_ = -1L;
    protected String userPin_;

    public SmartCardSigner( String myPKCS11Module, BaseUI ui, String baseDir )
            throws IOException
    {
        ui.baseMsg("Base Sets");
        BASE_DIR = baseDir;
        this.ui = ui;
        pkcs11Module = myPKCS11Module;
        setStandardsParameters();
        ui.baseMsg(" FINISHED");
    }

        public SmartCardSigner( String myPKCS11Module, String baseDir )
            throws IOException
    {
        ui.baseMsg("Base Sets");
        BASE_DIR = baseDir;
        ui = new StandardOutput();
        pkcs11Module = myPKCS11Module;
        setStandardsParameters();
        ui.baseMsg(" FINISHED");
    }

    public SmartCardSigner( String myPKCS11Module, BaseUI ui)
            throws IOException
    {
        ui.baseMsg("Base Sets");
        BASE_DIR = "~";
        this.ui = ui;
        pkcs11Module = myPKCS11Module;
        setStandardsParameters();
        ui.baseMsg(" FINISHED");
    }

    public SmartCardSigner( String myPKCS11Module)
            throws IOException
    {
        ui.baseMsg("Base Sets");
        BASE_DIR = "~";
        ui = new StandardOutput();
        pkcs11Module = myPKCS11Module;
        setStandardsParameters();
        ui.baseMsg(" FINISHED");
    }

    public void execute(String pin, String file)
    {
        try {
            initialize();
            getInfo();
            getSlotInfo();
            getTokenInfo();
            getMechanismInfo();
//            initToken();
            openROSession();
//            getSessionInfo();
//            findAllObjects();
//            printAllObjects();
            loginUser(pin);
//            getSessionInfo();
//            findAllObjects();
//            printAllObjects();
            findSignatureKey();
            findCertificate();
            readCertificate();
            writeCertificateToFile(BASE_DIR+CERTIFICATE_FILE);
            signData(file);
            writeSignatureToFile(BASE_DIR+SIGNATURE_FILE);
            digestData();
            writeDigestToFile(BASE_DIR+DIGEST_FILE);
            logout();
            closeSession();

        } catch (Throwable thr) {
            thr.printStackTrace();
        }
    }


    public void executeAndNoSave(String pin,String fileToSign)
    {
        try {
            initialize();
            getInfo();
            getSlotInfo();
            getTokenInfo();
            getMechanismInfo();
//            initToken();
            openROSession();
//            getSessionInfo();
//            findAllObjects();
//            printAllObjects();
            loginUser(pin);
//            getSessionInfo();
//            findAllObjects();
//            printAllObjects();
            findSignatureKey();
            findCertificate();
            readCertificate();
//            writeCertificateToFile(BASE_DIR+CERTIFICATE_FILE);
            signData(fileToSign);
//            writeSignatureToFile(BASE_DIR+SIGNATURE_FILE);
            digestData();
//            writeDigestToFile(BASE_DIR+DIGEST_FILE);
            logout();
            closeSession();

        } catch (Throwable thr) {
            thr.printStackTrace();
        }
    }

    public void executeFromStringAndNoSave(String pin,String stringToSign)
    {
        try {
            initialize();
            getInfo();
            getSlotInfo();
            getTokenInfo();
            getMechanismInfo();
//            initToken();
            openROSession();
//            getSessionInfo();
//            findAllObjects();
//            printAllObjects();
            loginUser(pin);
//            getSessionInfo();
//            findAllObjects();
//            printAllObjects();
            findSignatureKey();
            findCertificate();
            readCertificate();
//            writeCertificateToFile(BASE_DIR+CERTIFICATE_FILE);
            signDataString(stringToSign);
//            writeSignatureToFile(BASE_DIR+SIGNATURE_FILE);
            digestDataString();
//            writeDigestToFile(BASE_DIR+DIGEST_FILE);
            logout();
            closeSession();

        } catch (Throwable thr) {
            thr.printStackTrace();
        }
    }

   /**
   * Set signatureMechanism_ to CKM_MD5_RSA_PKCS and digestMechanism_ to CKM_SHA_1
   */
    public void setStandardsParameters()
    {
        signatureMechanism_ = new CK_MECHANISM();
        signatureMechanism_.mechanism = PKCS11Constants.CKM_MD5_RSA_PKCS;
        signatureMechanism_.pParameter = null;
        digestMechanism_ = new CK_MECHANISM();
        digestMechanism_.mechanism = PKCS11Constants.CKM_SHA_1;
        digestMechanism_.pParameter = null;
    }



  /**
   * Initialize the smartcard reader
   *
   * @throws PKCS11Exception
   * @throws IOException
   */
    public void initialize()
            throws PKCS11Exception,IOException
    {
        ui.baseMsg("initializing... ");
        System.out.println("\n\n"+pkcs11Module+"\n\n");
        myPKCS11Module_ = PKCS11Connector.connectToPKCS11Module(pkcs11Module);
        myPKCS11Module_.C_Initialize(null);
        ui.baseMsg("FINISHED\n");
    }


    //////////////
     public void getInfo()
      throws PKCS11Exception
  {
    ui.baseMsg("getting info");
    CK_INFO moduleInfo = myPKCS11Module_.C_GetInfo();
    ui.baseMsg("Module Info: ");
    ui.baseMsg(moduleInfo+"");
    ui.baseMsg("FINISHED\n");
  }

  public void getSlotInfo()
      throws PKCS11Exception
  {
    ui.baseMsg("getting slot list");
    long[] slotIDs = myPKCS11Module_.C_GetSlotList(false);
    CK_SLOT_INFO slotInfo;
    for (int i=0; i < slotIDs.length; i++) {
      ui.baseMsg("Slot Info: ");
      slotInfo = myPKCS11Module_.C_GetSlotInfo(slotIDs[i]);
      ui.baseMsg(slotInfo+"");
    }
    ui.baseMsg("FINISHED\n");
  }

    //////////////////

        /**
   * Get the list of aviable Token
   *
   * @throws PKCS11Exception
   * @return String[] where each element are a slot
   */
    public String[] getTokenInfoInStringArray()
            throws PKCS11Exception
    {
        String[] s;
        ui.baseMsg("getting token list");
        long[] tokenIDs = myPKCS11Module_.C_GetSlotList(true);
        CK_TOKEN_INFO tokenInfo;
        s = new String[tokenIDs.length];
        for (int i = 0; i < tokenIDs.length; i++) {
            ui.baseMsg("Token Info: ");
            tokenInfo = myPKCS11Module_.C_GetTokenInfo(tokenIDs[i]);
            ui.baseMsg(tokenInfo + "");
            s[i] = tokenInfo+"";
        }
        ui.baseMsg("FINISHED\n");
        return s;
    }

   /**
   * Get the list of aviable Token
   *
   * @throws PKCS11Exception
   */
    public void getTokenInfo()
            throws PKCS11Exception
    {
        ui.baseMsg("getting token list");
        long[] tokenIDs = myPKCS11Module_.C_GetSlotList(true);
        CK_TOKEN_INFO tokenInfo;
        for (int i = 0; i < tokenIDs.length; i++) {
            ui.baseMsg("Token Info: ");
            tokenInfo = myPKCS11Module_.C_GetTokenInfo(tokenIDs[i]);
            ui.baseMsg(tokenInfo + "");
            if (token_ == -1L) {
                token_ = tokenIDs[i];
            }
        }
        ui.baseMsg("FINISHED\n");
     }


    /**
   * Get the list of aviable Mechanism oor each token
   *
   * @throws PKCS11Exception
   * @return String[][] where each element are a list of MechanismInfo for each slot
   */
    public String[][] getMechanismInfo()
            throws PKCS11Exception
    {
        String[][] s;
        CK_MECHANISM_INFO mechanismInfo;
        ui.baseMsg("getting mechanism list");
        ui.baseMsg("getting slot list");
        long[] slotIDs = myPKCS11Module_.C_GetSlotList(true);
        s = new String[slotIDs.length][];
        for (int i = 0; i < slotIDs.length; i++)
        {
            ui.baseMsg("getting mechanism list for slot " + slotIDs[i]);
            long[] mechanismIDs = myPKCS11Module_.C_GetMechanismList(slotIDs[i]);
            s[i] = new String[mechanismIDs.length];
            for (int j = 0; j < mechanismIDs.length; j++) {
                ui.baseMsg("mechanism info for mechanism " + Functions.mechanismCodeToString(mechanismIDs[j]) +  ": ");
                mechanismInfo = myPKCS11Module_.C_GetMechanismInfo(slotIDs[i],mechanismIDs[j]);
                s[i][j] = Functions.mechanismCodeToString(mechanismIDs[j]);
                ui.baseMsg(mechanismInfo + "");
            }
        }
        ui.baseMsg("FINISHED\n");
        return s;
    }

   /**
   * Initialize a token
   *
   * @param long slotIDs The ID of Slot that u want use
   * @param String pin Pin of smartcard
   * @param String label ????????
    *
   * @throws PKCS11Exception
   */

    public void initToken( long slotIDs, String pin, String label)
            throws PKCS11Exception
    {
        userPin_ = pin;
        ui.baseMsg("init token");
        myPKCS11Module_.C_InitToken(slotIDs, userPin_.toCharArray(), label.toCharArray());
        ui.baseMsg("FINISHED");
    }

  /**
   * Initialize a token usinf first slot
   *
   * @param String pin Pin of smartcard
    *
   * @throws PKCS11Exception
   */
    public void initToken(String pin)
            throws PKCS11Exception
    {
        userPin_ = pin;
        String label = "The Label!                      ";
        ui.baseMsg("init token");
        long[] slotIDs = myPKCS11Module_.C_GetSlotList(false);
        myPKCS11Module_.C_InitToken(slotIDs[0], userPin_.toCharArray(), label.toCharArray());
        ui.baseMsg("FINISHED");
    }

   /**
   * Open a ReadOnlySession
   *
   * @throws PKCS11Exception
   */
    public void openROSession()
      throws PKCS11Exception
    {
        ui.baseMsg("open RO session");
        session_ = myPKCS11Module_.C_OpenSession(token_, PKCS11Constants.CKF_SERIAL_SESSION, null, null);
        ui.baseMsg("FINISHED\n");
    }

   /**
   * Open a ReadOnlySession
   *
   * @param long rapresents the token to use to open teh session
    *
   * @throws PKCS11Exception
   */
    public void openROSession(long token)
      throws PKCS11Exception
    {
        ui.baseMsg("open RO session");
        session_ = myPKCS11Module_.C_OpenSession(token, PKCS11Constants.CKF_SERIAL_SESSION, null, null);
        ui.baseMsg("FINISHED\n");
    }

    /**
   * Login user to the session wit Pin
   *
   * @param Pin of smartcard
    *
   * @throws PKCS11Exception
   */
    public void loginUser(String userPin)
            throws PKCS11Exception
    {
        ui.baseMsg("login user to session with password");
        myPKCS11Module_.C_Login(session_, PKCS11Constants.CKU_USER, userPin.toCharArray());
        ui.baseMsg("FINISHED\n");
    }

    /**
   * Search a signature key in the smartcard end set the first in signatureKeyHandle_
    *
   * @throws PKCS11Exception
   */
    public void findSignatureKey()
            throws PKCS11Exception
    {
        ui.baseMsg("find signature key");
        CK_ATTRIBUTE[] attributeTemplateList = new CK_ATTRIBUTE[2];

        attributeTemplateList[0] = new CK_ATTRIBUTE();
        attributeTemplateList[0].type = PKCS11Constants.CKA_CLASS;
        attributeTemplateList[0].pValue = new Long(PKCS11Constants.CKO_PRIVATE_KEY);
        attributeTemplateList[1] = new CK_ATTRIBUTE();
        attributeTemplateList[1].type = PKCS11Constants.CKA_SIGN;
        attributeTemplateList[1].pValue = new Boolean(PKCS11Constants.TRUE);

        myPKCS11Module_.C_FindObjectsInit(session_, attributeTemplateList);
        long[] availableSignatureKeys = myPKCS11Module_.C_FindObjects(session_, 100); //maximum of 100 at once
        if (availableSignatureKeys == null) {
            ui.baseMsg("null returned - no signature key found");
        } else {
            ui.baseMsg("found " + availableSignatureKeys.length + " signature keys");
            for (int i = 0; i < availableSignatureKeys.length; i++) {
                if (i == 0) { // the first we find, we take as our signature key
                    signatureKeyHandle_ = availableSignatureKeys[i];
                    ui.baseMsg("for signing we use ");
                }
                ui.baseMsg("signature key " + i);
            }
        }
        myPKCS11Module_.C_FindObjectsFinal(session_);
        ui.baseMsg("FINISHED\n");
    }

    /**
   * Search a certificate in the smartcard with the signatureKeyHandle_ end set in certificateHandle_
    *
   * @throws PKCS11Exception
   */
    public void findCertificate()
            throws PKCS11Exception
    {
        ui.baseMsg("find certificate");

        // first get the ID of the signature key
        CK_ATTRIBUTE[] attributeTemplateList = new CK_ATTRIBUTE[1];
        attributeTemplateList[0] = new CK_ATTRIBUTE();
        attributeTemplateList[0].type = PKCS11Constants.CKA_ID;

        myPKCS11Module_.C_GetAttributeValue(session_, signatureKeyHandle_, attributeTemplateList);
        byte[] keyAndCertificateID = (byte[]) attributeTemplateList[0].pValue;
        ui.baseMsg("ID of siganture key: " + Functions.toHexString(keyAndCertificateID));

        // now get the certificate with the same ID as the signature key
        attributeTemplateList = new CK_ATTRIBUTE[2];

        attributeTemplateList[0] = new CK_ATTRIBUTE();
        attributeTemplateList[0].type = PKCS11Constants.CKA_CLASS;
        attributeTemplateList[0].pValue = new Long(PKCS11Constants.CKO_CERTIFICATE);
        attributeTemplateList[1] = new CK_ATTRIBUTE();
        attributeTemplateList[1].type = PKCS11Constants.CKA_ID;
        attributeTemplateList[1].pValue = keyAndCertificateID;

        myPKCS11Module_.C_FindObjectsInit(session_, attributeTemplateList);
        long[] availableCertificates = myPKCS11Module_.C_FindObjects(session_, 100); //maximum of 100 at once
        if (availableCertificates == null) {
            ui.baseMsg("null returned - no certificate found");
        } else {
            ui.baseMsg("found " + availableCertificates.length + " certificates with matching ID");
            for (int i = 0; i < availableCertificates.length; i++) {
                if (i == 0) { // the first we find, we take as our certificate
                    certificateHandle_ = availableCertificates[i];
                    ui.baseMsg("for verification we use ");
                }
                ui.baseMsg("certificate " + i);
            }
        }
        myPKCS11Module_.C_FindObjectsFinal(session_);
        ui.baseMsg("FINISHED\n");
    }

    /*
     * TO-DO - Write all next functions to save file in byte array or sometyng else
     *  and not use file on hd
     */


   /**
   * Read certificate (and save it in derEncodedCertificate_) from smarcard using certificateHandle_
   *
   * @throws PKCS11Exception
   */
    public void readCertificate()
            throws PKCS11Exception {
        ui.baseMsg("read certificate");

        CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[1];
        template[0] = new CK_ATTRIBUTE();
        template[0].type = PKCS11Constants.CKA_VALUE;
        myPKCS11Module_.C_GetAttributeValue(session_, certificateHandle_, template);
        derEncodedCertificate_ = (byte[]) template[0].pValue;
        ui.baseMsg("DER encoded certificate (" + derEncodedCertificate_.length + " bytes):");
        ui.baseMsg(Functions.toHexString(derEncodedCertificate_));

        ui.baseMsg("FINISHED\n");
    }


   /**
   * Write certificate in a file from derEncodedCertificate_
   *
   * @param  String cert_pat Location to save certificate
   * @throws PKCS11Exception
   */
    public void writeCertificateToFile(String cert_path)
            throws IOException, PKCS11Exception 
    {
        CERTIFICATE_FILE = cert_path;
        ui.baseMsg("write certificate to file: " + CERTIFICATE_FILE);

        FileOutputStream fos = new FileOutputStream(CERTIFICATE_FILE);
        fos.write(derEncodedCertificate_);
        fos.flush();
        fos.close();

        ui.baseMsg("FINISHED\n");
    }

   /**
   * Get the certificate
   *
   */
    public byte[] getCertificateInByte()
    {
        return derEncodedCertificate_;
    }

       /**
   * Get the certificate in string
   *
   */
    public String getCertificateInString()
    {
        return Functions.toHexString(derEncodedCertificate_);
    }


   /**
   * Sign data (file) and save it su signature_
   *
   * @param  String file Location of data to signe
   * @throws PKCS11Exception
   */
    public void signData(String file)
            throws IOException, PKCS11Exception 
    {
        file_ = file;
        byte[] buffer = new byte[1024];
        byte[] helpBuffer;
        int bytesRead;

        InputStream dataInput = new FileInputStream(file_);
        myPKCS11Module_.C_SignInit(session_, signatureMechanism_, signatureKeyHandle_);
        while ((bytesRead = dataInput.read(buffer, 0, buffer.length)) >= 0) {
            helpBuffer = new byte[bytesRead]; // we need a buffer that only holds what to send for signing
            System.arraycopy(buffer, 0, helpBuffer, 0, bytesRead);
            myPKCS11Module_.C_SignUpdate(session_, helpBuffer);
            Arrays.fill(helpBuffer, (byte) 0);
        }
        Arrays.fill(buffer, (byte) 0);
        signature_ = myPKCS11Module_.C_SignFinal(session_);
    }



    public void signDataString(String data)
            throws IOException, PKCS11Exception
    {
        byte[] buffer = new byte[1024];
        byte[] helpBuffer;
        int bytesRead;

        InputStream dataInput = new ByteArrayInputStream(data.getBytes());
        myPKCS11Module_.C_SignInit(session_, signatureMechanism_, signatureKeyHandle_);
        while ((bytesRead = dataInput.read(buffer, 0, buffer.length)) >= 0) {
            helpBuffer = new byte[bytesRead]; // we need a buffer that only holds what to send for signing
            System.arraycopy(buffer, 0, helpBuffer, 0, bytesRead);
            myPKCS11Module_.C_SignUpdate(session_, helpBuffer);
            Arrays.fill(helpBuffer, (byte) 0);
        }
        Arrays.fill(buffer, (byte) 0);
        signature_ = myPKCS11Module_.C_SignFinal(session_);
    }


   /**
   * Write sign data in to a File
   *
   * @param  String signatureFile Location to save signature
   * @throws PKCS11Exception
   */
    public void writeSignatureToFile(String signatureFile)
            throws IOException, PKCS11Exception 
    {
        SIGNATURE_FILE = signatureFile;
        ui.baseMsg("write signature to file: " + SIGNATURE_FILE);

        FileOutputStream fos = new FileOutputStream(SIGNATURE_FILE);
        fos.write(signature_);
        fos.flush();
        fos.close();

        ui.baseMsg("FINISHED");
    }

       /**
   * Get Signature in byte array
   */
    public byte[] getSignatureInByteArray()
    {
        return signature_;
    }

           /**
   * Get Signature in String
   */
    public String getSignatureInString()
    {
        return  Functions.toHexString(signature_);
    }

   /**
   * Create Digest of Signature
   *
   * @throws PKCS11Exception
   * @throws IOException
   */
    public void digestData()
            throws IOException, PKCS11Exception {
        byte[] buffer = new byte[1024];
        byte[] helpBuffer, testDigest;
        int bytesRead;
        ui.baseMsg("Digest Data");
        myPKCS11Module_.C_DigestInit(session_, digestMechanism_);
        try {
            messageDigest_ = MessageDigest.getInstance("SHA-1");
        } catch (Exception e) {
            ui.baseMsg(e + "");
        }
        InputStream dataInput = new FileInputStream(file_);
        while ((bytesRead = dataInput.read(buffer, 0, buffer.length)) >= 0) {
            helpBuffer = new byte[bytesRead]; // we need a buffer that only holds what to send for digesting
            System.arraycopy(buffer, 0, helpBuffer, 0, bytesRead);
            myPKCS11Module_.C_DigestUpdate(session_, helpBuffer);
            messageDigest_.update(helpBuffer);
            Arrays.fill(helpBuffer, (byte) 0);
        }
        Arrays.fill(buffer, (byte) 0);
        digest_ = myPKCS11Module_.C_DigestFinal(session_);
        testDigest = messageDigest_.digest();
        ui.baseMsg("PKCS11digest:" + Functions.toHexString(digest_));
        ui.baseMsg("TestDigest  :" + Functions.toHexString(testDigest));
        ui.baseMsg("FINISHED\n");
    }

   /**
   * Create Digest of Signature
   *
   * @throws PKCS11Exception
   * @throws IOException
   */
    public void digestDataString()
            throws IOException, PKCS11Exception {
        byte[] buffer = new byte[1024];
        byte[] helpBuffer, testDigest;
        int bytesRead;
        ui.baseMsg("Digest Data");
        myPKCS11Module_.C_DigestInit(session_, digestMechanism_);
        try {
            messageDigest_ = MessageDigest.getInstance("SHA-1");
        } catch (Exception e) {
            ui.baseMsg(e + "");
        }
        InputStream dataInput = new ByteArrayInputStream(getSignatureInString().getBytes());
        while ((bytesRead = dataInput.read(buffer, 0, buffer.length)) >= 0) {
            helpBuffer = new byte[bytesRead]; // we need a buffer that only holds what to send for digesting
            System.arraycopy(buffer, 0, helpBuffer, 0, bytesRead);
            myPKCS11Module_.C_DigestUpdate(session_, helpBuffer);
            messageDigest_.update(helpBuffer);
            Arrays.fill(helpBuffer, (byte) 0);
        }
        Arrays.fill(buffer, (byte) 0);
        digest_ = myPKCS11Module_.C_DigestFinal(session_);
        testDigest = messageDigest_.digest();
        ui.baseMsg("PKCS11digest:" + Functions.toHexString(digest_));
        ui.baseMsg("TestDigest  :" + Functions.toHexString(testDigest));
        ui.baseMsg("FINISHED\n");
    }

   /**
   * Write Digest in a file
   *
   * @param String path Location to save digest file
   * @throws PKCS11Exception
   * @throws IOException
   */
    public void writeDigestToFile(String path)
            throws IOException, PKCS11Exception 
    {
        DIGEST_FILE = path;
        ui.baseMsg("write digest to file: " + DIGEST_FILE);

        FileOutputStream fos = new FileOutputStream(DIGEST_FILE);
        fos.write(digest_);
        fos.flush();
        fos.close();

        ui.baseMsg("FINISHED\n");
    }


   /*
   * Get Digest in byte array
   */
    public byte[] getDigestInByteArray()
    {
        return digest_;
    }

       /*
   * Get Digest in String
   */
    public String getDigestInString()
    {
        return Functions.toHexString(digest_);
    }


   /**
   * logout from session
   *
   * @throws PKCS11Exception
   */
    public void logout()
            throws PKCS11Exception {
        ui.baseMsg("logout session");
        myPKCS11Module_.C_Logout(session_);
        ui.baseMsg("FINISHED\n");
    }

   /**
   * Close session
   *
   * @throws PKCS11Exception
   */
    public void closeSession()
            throws PKCS11Exception {
        ui.baseMsg("close session");
        myPKCS11Module_.C_CloseSession(session_);
        ui.baseMsg("FINISHED\n");
    }
}




/**
 public void getSlotInfo()
      throws PKCS11Exception
  {
    ui.baseMsg("getting slot list");
    long[] slotIDs = myPKCS11Module_.C_GetSlotList(false);
    CK_SLOT_INFO slotInfo;
    for (int i=0; i < slotIDs.length; i++) {
      ui.baseMsg("Slot Info: ");
      slotInfo = myPKCS11Module_.C_GetSlotInfo(slotIDs[i]);
      ui.baseMsg(slotInfo+"");
    }
    ui.baseMsg("FINISHED\n");
  }

 public void getTokenInfo()
      throws PKCS11Exception
  {
    ui.baseMsg("getting token list");
    long[] tokenIDs = myPKCS11Module_.C_GetSlotList(true);
    CK_TOKEN_INFO tokenInfo;
    for (int i=0; i < tokenIDs.length; i++) {
      ui.baseMsg("Token Info: ");
      tokenInfo = myPKCS11Module_.C_GetTokenInfo(tokenIDs[i]);
      ui.baseMsg(tokenInfo+"");
      if (token_ == -1L) {
        token_ = tokenIDs[i];
      }
    }
    ui.baseMsg("FINISHED\n");
  }

   public void findAllObjects()
      throws PKCS11Exception
  {
    ui.baseMsg("find all objects");
    myPKCS11Module_.C_FindObjectsInit(session_, null);
    objects_ = myPKCS11Module_.C_FindObjects(session_, 100); //maximum of 100 at once
    if (objects_ == null) {
      ui.baseMsg("null returned - no objects found");
    } else {
      ui.baseMsg("found " + objects_.length + " objects");
    }
    myPKCS11Module_.C_FindObjectsFinal(session_);
    ui.baseMsg("FINISHED\n");
  }

  public void printAllObjects()
      throws PKCS11Exception
  {
    ui.baseMsg("print all objects");

    for (int i = 0; i < objects_.length; i++) {
      ui.baseMsg("object No. " + i);
      CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[1];
      template[0] = new CK_ATTRIBUTE();
      template[0].type = PKCS11Constants.CKA_CLASS;
      myPKCS11Module_.C_GetAttributeValue(session_, objects_[i], template);
      ui.baseMsg("CKA_CLASS: " + Functions.classTypeToString(((Long) template[0].pValue).longValue()));
    }

    ui.baseMsg("FINISHED\n");
  }



 **/