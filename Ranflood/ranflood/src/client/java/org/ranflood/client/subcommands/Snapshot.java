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

package org.ranflood.client.subcommands;

import static org.ranflood.client.subcommands.Utils.*;
import static org.ranflood.common.RanfloodLogger.*;

import java.io.File;
import java.util.Collection;
import java.util.concurrent.Callable;
import java.util.stream.Collectors;

import org.ranflood.client.binders.ZMQ_JSON_Client;
import org.ranflood.common.FloodMethod;
import org.ranflood.common.commands.SnapshotCommand;
import org.ranflood.common.commands.transcoders.ParseException;
import org.ranflood.common.commands.types.RanfloodType;

import picocli.CommandLine;

@CommandLine.Command(
				name = "snapshot",
				mixinStandardHelpOptions = true,
				description = { "management of folder/file snapshots" },
				subcommands = {
								Snapshot.Take.class,
								Snapshot.Remove.class,
								Snapshot.List.class
				}
)
public class Snapshot implements Callable< Integer > {

	@Override
	public Integer call() {
		new CommandLine( this ).usage( System.err );
		return 1;
	}

	@CommandLine.Command(
					name = "take",
					mixinStandardHelpOptions = true,
					description = { "take a new snapshot" }
	)
	static class Take implements Callable< Integer > {

		@CommandLine.Parameters(index = "0", arity = "1")
		String method;

		@CommandLine.Parameters(index = "1..*", arity = "1..*")
		Collection< File > targetFolders;

		@CommandLine.Option(names = { "-t", "--timeout" }, description = "Set the call timeout of the client in seconds (default is 10)")
		private Integer timeout = 10;

		@CommandLine.Option(names = { "-a", "--address" }, description = "Set the address of the daemon (default is \"tcp://192.168.77.189:7890\")")
		private String address = "tcp://192.168.77.189:7890";

		@Override
		public Integer call() {
			System.out.println( "Requesting the taking of snapshots of the following folders." );
			try {
				FloodMethod m = getMethod( method );
				targetFolders.forEach( t -> {
					SnapshotCommand.Add c =
									new SnapshotCommand.Add( new RanfloodType( m, t.toPath().toAbsolutePath() ) );
					System.out.println( new ZMQ_JSON_Client( address, timeout ).sendCommand( c ) );
				} );
				return 0;
			} catch ( ParseException e ) {
				error( "Method " + method + " not supported." );
				return 1;
			}
		}
	}

	@CommandLine.Command(
					name = "remove",
					mixinStandardHelpOptions = true,
					description = { "removes the snapshots of a list of folders" }
	)
	static class Remove implements Callable< Integer > {

		@CommandLine.Parameters(index = "0", arity = "1")
		String method;

		@CommandLine.Parameters(index = "1..*", arity = "1..*")
		Collection< File > targetFolders;

		@CommandLine.Option(names = { "-t", "--timeout" }, description = "Set the call timeout of the client in seconds (default is 10)")
		private Integer timeout = 10;

		@CommandLine.Option(names = { "-a", "--address" }, description = "Set the address of the daemon (default is \"tcp://192.168.77.189:7890\")")
		private String address = "tcp://192.168.77.189:7890";

		@Override
		public Integer call() {
			System.out.println( "Requesting the removal of snapshots of the following folders." );
			try {
				FloodMethod m = getMethod( method );
				targetFolders.forEach( t -> {
					SnapshotCommand.Remove c =
									new SnapshotCommand.Remove( new RanfloodType( m, t.toPath().toAbsolutePath() ) );
					System.out.println( new ZMQ_JSON_Client( address, timeout ).sendCommand( c ) );
				} );
				return 0;
			} catch ( ParseException e ) {
				error( "Method " + method + " not supported." );
				return 1;
			}
		}
	}

	@CommandLine.Command(
					name = "list",
					mixinStandardHelpOptions = true,
					description = { "list the snapshots currently saved" }
	)
	static class List implements Callable< Integer > {

		@CommandLine.Option(names = { "-t", "--timeout" }, description = "Set the call timeout of the client in seconds (default is 10)")
		private Integer timeout = 10;

		@CommandLine.Option(names = { "-a", "--address" }, description = "Set the address of the daemon (default is \"tcp://192.168.77.189:7890\")")
		private String address = "tcp://192.168.77.189:7890";

		@Override
		public Integer call() {
			System.out.println( "Requesting the list of snapshots." );
			SnapshotCommand.List c = new SnapshotCommand.List();
			java.util.List< RanfloodType > l = new ZMQ_JSON_Client( address, timeout ).sendListCommand( c );
			if ( l.isEmpty() ) {
				System.out.println( "There are no snapshots at the moment" );
			} else {
				System.out.println( l.stream()
								.map( r -> r.method().name() + " | " + r.path() )
								.collect( Collectors.joining( "\n" ) ) );
			}
			return 0;
		}
	}

}
