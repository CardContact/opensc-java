/***********************************************************
 * $Id: PKCS11DSAKeyPairGenerator.java 33 2007-01-26 19:37:44Z wolfgang.glas $
 * 
 * PKCS11 provider of the OpenSC project http://www.opensc-project.org
 *
 * Copyright (C) 2002-2006 ev-i Informationstechnologie GmbH
 *
 * Created: Jan 25, 2007
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 * 
 ***********************************************************/

package org.opensc.pkcs11.wrap;

import java.security.PrivateKey;
import java.security.PublicKey;

import org.opensc.pkcs11.spec.PKCS11DSAKeyPairGenParameterSpec;

/**
 * @author wglas
 *
 */
public class PKCS11DSAKeyPairGenerator extends PKCS11KeyPairGenerator
{
    static private final int N_EXTRA_PRIVATE_ATTRIBUTES = 0;
    static private final int N_EXTRA_PUBLIC_ATTRIBUTES = 3;
    
    private PKCS11DSAKeyPairGenParameterSpec params;
    
    /**
     * Create a new PKCS11 key pair generator.
     * 
     * @param session The underlying PKCS11 session.
     * @param params The parameters for this initialization.
     */
    public PKCS11DSAKeyPairGenerator(PKCS11DSAKeyPairGenParameterSpec params)
    {
        super(PKCS11Mechanism.CKM_DSA_KEY_PAIR_GEN);
        
        super.initStaticPublicAttrs(params, N_EXTRA_PUBLIC_ATTRIBUTES);
        super.pubKeyAttributes[N_STATIC_PUBLIC_ATTRIBUTES+0] =
            new PKCS11Attribute(PKCS11Attribute.CKA_PRIME,
                                params.getP().toByteArray());
        super.pubKeyAttributes[N_STATIC_PUBLIC_ATTRIBUTES+1] =
            new PKCS11Attribute(PKCS11Attribute.CKA_SUBPRIME,
                                params.getQ().toByteArray());
        super.pubKeyAttributes[N_STATIC_PUBLIC_ATTRIBUTES+2] =
            new PKCS11Attribute(PKCS11Attribute.CKA_BASE,
                                params.getG().toByteArray());

        super.initStaticPrivateAttrs(params, N_EXTRA_PRIVATE_ATTRIBUTES);
        
        this.params = params;
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs11.wrap.PKCS11KeyPairGenerator#makePrivateKey(long)
     */
    @Override
    protected PrivateKey makePrivateKey(PKCS11Session session, long handle) throws PKCS11Exception
    {
        if (this.params.isExtractable() && ! this.params.isSensitive())
            return new PKCS11DSAPrivateKey(session,handle);
        else
            return new PKCS11NeDSAPrivateKey(session,handle);
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs11.wrap.PKCS11KeyPairGenerator#makePublicKey(long)
     */
    @Override
    protected PublicKey makePublicKey(PKCS11Session session, long handle) throws PKCS11Exception
    {
        return new PKCS11DSAPublicKey(session,handle);
    }

}
