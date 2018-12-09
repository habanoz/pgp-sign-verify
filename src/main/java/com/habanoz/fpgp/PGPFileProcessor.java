package com.habanoz.fpgp;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

public class PGPFileProcessor {

	private String signerPass;
	private String decryptorPass;
	private File decryptorPublicKeyFile;
	private File decryptorSecretKeyFile;
	private File signerSecretKeyFile;
	private File signerPublicKeyFile;

	private boolean asciiArmored = false;
	private boolean integrityCheck = true;

	public PGPFileProcessor(File signerSecretKeyFile, String signerPass, File decryptorPublicKeyFile) {
		this.signerPass = signerPass;
		this.decryptorPublicKeyFile = decryptorPublicKeyFile;
		this.signerSecretKeyFile = signerSecretKeyFile;
	}

	public PGPFileProcessor(File signerPublicKeyFile, File signerSecretKeyFile, String signerPass, File decryptorPublicKeyFile, File decryptorSecretKeyFile, String decryptorPass) {
		this.signerPublicKeyFile = signerPublicKeyFile;
		this.signerPass = signerPass;
		this.decryptorPublicKeyFile = decryptorPublicKeyFile;
		this.signerSecretKeyFile = signerSecretKeyFile;
		this.decryptorSecretKeyFile = decryptorSecretKeyFile;
		this.decryptorPass = decryptorPass;
	}


	public boolean signEncrypt(File inputFile, File outputFile) throws Exception {
		FileInputStream decryptorPublicKeyIn = new FileInputStream(decryptorPublicKeyFile);
		FileInputStream signerSecretKeyIn = new FileInputStream(signerSecretKeyFile);

		PGPPublicKey decryptorPublicKey = PGPUtils.readPublicKey(decryptorPublicKeyIn);
		PGPSecretKey signerSecretKey = PGPUtils.readSecretKey(signerSecretKeyIn);

		PGPUtils.signEncryptFile(
				outputFile,
				inputFile,
				decryptorPublicKey,
				signerSecretKey,
				this.getSignerPass(),
				this.isAsciiArmored(),
				this.isIntegrityCheck());

		decryptorPublicKeyIn.close();
		signerSecretKeyIn.close();

		return true;
	}

	public boolean decrypt(File signedFile, File decryptedFile) throws Exception {
		FileInputStream signedFileIn = new FileInputStream(signedFile);
		FileInputStream decryptorSecretKeyIn = new FileInputStream(decryptorSecretKeyFile);
		FileOutputStream decryptedOut = new FileOutputStream(decryptedFile);

		PGPUtils.decryptFile(signedFileIn, decryptedOut, decryptorSecretKeyIn, decryptorPass.toCharArray());

		signedFileIn.close();
		decryptedOut.close();
		decryptorSecretKeyIn.close();
		return true;
	}

	public boolean decryptSigned(File signedFile, File decryptedFile) throws Exception {
		return PGPUtils.decryptSignedFile(signedFile, decryptedFile, decryptorSecretKeyFile, signerPublicKeyFile, decryptorPass.toCharArray());
	}

	public boolean isAsciiArmored() {
		return asciiArmored;
	}

	public void setAsciiArmored(boolean asciiArmored) {
		this.asciiArmored = asciiArmored;
	}

	public boolean isIntegrityCheck() {
		return integrityCheck;
	}

	public void setIntegrityCheck(boolean integrityCheck) {
		this.integrityCheck = integrityCheck;
	}

	public String getSignerPass() {
		return signerPass;
	}

	public void setSignerPass(String signerPass) {
		this.signerPass = signerPass;
	}

	public String getDecryptorPass() {
		return decryptorPass;
	}

	public void setDecryptorPass(String decryptorPass) {
		this.decryptorPass = decryptorPass;
	}

	public File getDecryptorPublicKeyFile() {
		return decryptorPublicKeyFile;
	}

	public void setDecryptorPublicKeyFile(File decryptorPublicKeyFile) {
		this.decryptorPublicKeyFile = decryptorPublicKeyFile;
	}

	public File getDecryptorSecretKeyFile() {
		return decryptorSecretKeyFile;
	}

	public void setDecryptorSecretKeyFile(File decryptorSecretKeyFile) {
		this.decryptorSecretKeyFile = decryptorSecretKeyFile;
	}

	public File getSignerSecretKeyFile() {
		return signerSecretKeyFile;
	}

	public void setSignerSecretKeyFile(File signerSecretKeyFile) {
		this.signerSecretKeyFile = signerSecretKeyFile;
	}

	public File getSignerPublicKeyFile() {
		return signerPublicKeyFile;
	}

	public void setSignerPublicKeyFile(File signerPublicKeyFile) {
		this.signerPublicKeyFile = signerPublicKeyFile;
	}
}