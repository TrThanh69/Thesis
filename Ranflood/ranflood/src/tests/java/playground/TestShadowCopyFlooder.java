/******************************************************************************
 * Copyright 2021 (C) by Saverio Giallorenzo <saverio.giallorenzo@gmail.com>  *
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

package playground;

import static org.ranflood.common.RanfloodLogger.*;
import static org.ranflood.common.commands.transcoders.JSONTranscoder.*;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import org.ranflood.common.FloodMethod;
import org.ranflood.common.commands.Command;
import org.ranflood.common.commands.FloodCommand;
import org.ranflood.common.commands.SnapshotCommand;
import org.ranflood.common.commands.transcoders.JSONTranscoder;
import org.ranflood.common.commands.transcoders.ParseException;
import org.ranflood.common.commands.types.RanfloodType;
import org.ranflood.daemon.Ranflood;
import org.zeromq.SocketType;
import org.zeromq.ZContext;
import org.zeromq.ZMQ;


public class TestShadowCopyFlooder {

	public static void main( String[] args ) throws InterruptedException, IOException {

		Ranflood.main( TestCommons.getArgs() );
		Thread.sleep( 1000 );
		List< Path > filePaths = List.of(
						Path.of( "/home/trthanh/Desktop/Ranflood/ranflood_testsite/attackedFolder/Other" ),
						Path.of( "/home/trthanh/Desktop/Ranflood/ranflood_testsite/attackedFolder/Other 2" )
		);

		// we set the folders up for the copy
		for ( Path filePath : filePaths ) {
			if ( !filePath.toFile().exists()
							|| !filePath.toFile().isDirectory()
							|| Objects.requireNonNull( filePath.toFile().listFiles() ).length < 1
			) {
				createTestStructure( filePath );
			}
		}

		for ( Path filePath : filePaths ) {
			sendCommand( new SnapshotCommand.Add(
							new RanfloodType( FloodMethod.SHADOW_COPY, filePath ) )
			);
		}


		List< RanfloodType.Tagged > list;
		do {
			log( "Retrieving list of available snapshots" );
			String runningList = sendCommandList( new SnapshotCommand.List() );
			log( runningList );
			list = ( List< RanfloodType.Tagged > ) parseDaemonCommandList( runningList );
			Thread.sleep( 1000 );
		} while ( list.size() < filePaths.size() );

		for ( Path filePath : filePaths ) {
			sendCommand( new FloodCommand.Start(
							new RanfloodType( FloodMethod.SHADOW_COPY, filePath )
			) );
		}
		Thread.sleep( 1000 );

		do {
			log( "Retrieving list of running floods" );
			String runningList = sendCommandList( new FloodCommand.List() );
			log( runningList );
			list = ( List< RanfloodType.Tagged > ) parseDaemonCommandList( runningList );
			Thread.sleep( 1000 );
		} while ( list.size() < filePaths.size() );

		Thread.sleep( 5000 );

		for ( RanfloodType.Tagged rftt : list ) {
			// THIS SHOULD BE OK
			sendCommand( new FloodCommand.Stop(
							rftt.method(),
							rftt.id()
			) );
		}
		Thread.sleep( 1000 );

		Ranflood.daemon().shutdown();

//		sendString( "shutdown" );

//		Thread.sleep( 1000 );
		//Ranflood.getDaemon().shutdown();
	}

	private static void createTestStructure( Path root ) throws IOException, InterruptedException {
		log( "Creating test folders structure" );
		List< Path > l = Arrays.asList(
						root.resolve( "Application Data" ), root.resolve( "Application Data" ).resolve( "Other" ),
						root.resolve( "Other" ), root.resolve( "Other 2" )
		);
		l.forEach( f -> {
			sendCommand( new FloodCommand.Start(
							new RanfloodType( FloodMethod.RANDOM, f )
			) );
		} );
		Thread.sleep( 1000 );
		// THIS SHOULD BE OK
		List< RanfloodType.Tagged > list;
		do {
			log( "Retrieving list of running floods" );
			String runningList = sendCommandList( new FloodCommand.List() );
			log( runningList );
			list = ( List< RanfloodType.Tagged > ) parseDaemonCommandList( runningList );
			Thread.sleep( 250 );
		} while ( list.size() < l.size() );

		for ( RanfloodType.Tagged rftt : list ) {
			// THIS SHOULD BE OK
			sendCommand( new FloodCommand.Stop(
							rftt.method(),
							rftt.id()
			) );
		}
		Thread.sleep( 1000 );
	}

	private static void sendCommand( Command< ? > c ) {
		try {
			sendString( JSONTranscoder.toJsonString( c ) );
		} catch ( ParseException e ) {
			e.printStackTrace();
		}
	}

	private static void sendString( String s ) {
		try ( ZContext context = new ZContext() ) {
			ZMQ.Socket socket = context.createSocket( SocketType.REQ );
			socket.connect( "tcp://192.168.77.189:7890" );
			socket.send( s );
			String response = new String( socket.recv(), ZMQ.CHARSET );
			log( "Client received [" + response + "]" );
			socket.close();
			context.destroy();
		}
	}

	private static String sendCommandList( Command< ? > c ) {
		try ( ZContext context = new ZContext() ) {
			ZMQ.Socket socket = context.createSocket( SocketType.REQ );
			socket.connect( "tcp://192.168.77.189:7890" );
			String command = JSONTranscoder.toJsonString( c );
			socket.send( command );
			String response = new String( socket.recv(), ZMQ.CHARSET );
			socket.close();
			context.destroy();
			return response;
//			return Json.parse( response ).asObject().getArray( "list" ).getString( 0 );
		} catch ( ParseException e ) {
			e.printStackTrace();
			return "";
		}
	}

}