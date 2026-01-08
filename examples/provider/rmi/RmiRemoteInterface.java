/* RmiRemoteInterface.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

import java.util.List;
import java.rmi.Remote;
import java.rmi.RemoteException;

/**
 * Interface defining the remote object interface.
 */
public interface RmiRemoteInterface extends Remote {
    String getMessage() throws RemoteException;
    byte[] getByteArray() throws RemoteException;
    void sendMessage(String message) throws RemoteException;
    void sendByteArray(byte[] arr) throws RemoteException;
    int[] getRegistryPorts() throws RemoteException;
}


