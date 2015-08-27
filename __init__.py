#!/usr/bin/env python

# ssh key management
from os.path import  isdir
import os
import pwd
import sshpubkeys
import unittest

class SSHAuthorizedKeysEntry(sshpubkeys.SSHKey):
    def comment(self):
        return ' '.join(self.keydata.split(' ')[2:]).strip()

    def __repr__(self):
        reprstr = '{hash}: {self.bits} bit {self.key_type} ({comment})'
        return reprstr.format(self=self, 
                hash=self.hash(), comment=self.comment())

class SSHAuthorizedKeysFile():
    # This class makes the relatively acceptable assumption that
    # the AuthorizedHostKeys file in sshd's config file is not
    # changed from the default of %h/.ssh/authorized_keys
    def __init__(self, username):
        try:
            user = pwd.getpwnam(username)
        except KeyError:
            raise KeyError('User %s does not exist'%(username,))

        if not isdir(user.pw_dir):
            raise ValueError('User home directory does not exist')

        ssh_path = user.pw_dir + '/.ssh/'

        if not isdir(ssh_path):
            os.mkdir(ssh_path)
            os.chown(ssh_path, user.pw_uid, user.pw_gid)
        
        self.filename = ssh_path + 'authorized_keys'

        if os.path.isfile(self.filename):
            self.keys = [SSHAuthorizedKeysEntry(key) for key in open(self.filename, 'r')]
        else:
            self.keys = []

    def append(self, keydata):
        if type(keydata) is str:
            if keydata in [k.keydata for k in self.keys]:
                raise ValueError('Key already in file')
            try:
                key = SSHAuthorizedKeysEntry(keydata)
            except Exception as e:
                raise ValueError(e)

        elif type(keydata) is SSHAuthorizedKeysEntry:
            key = keydata
            if key.keydata in [k.keydata.strip() for k in self.keys]:
                raise ValueError('Key already in file')

        else:
            raise TypeError('keydata must be string or SSH Key object')

        open(self.filename, 'a').write(key.keydata + '\n')
        self.keys.append(key)

    def __getitem__(self, key):
        return self.keys[key]

    def __delitem__(self, key):
        ssh_key = self.keys[key]
        
        with open(self.filename, 'r') as keyfile:
            keyfile_entries = [x.strip() for x in keyfile.readlines()]

        with open(self.filename, 'w') as keyfile:
            for keydata in keyfile_entries:
                if ssh_key.keydata != keydata:
                    keyfile.write(keydata + '\n')

        self.keys.remove(ssh_key)

import tempfile
class SSHAuthorizedKeysGoodUsersTest(unittest.TestCase):
    valid_dummy_key_1 = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAYQDW7Y0E8nThXSJPtvF3g' + \
            'pLLhj7E1VlTVG36wArMZ71LByjaqtfFI/PcWLIu6Bf5YdRNsv/M8sdk4mRslWFofEL8Uk' + \
            'rwAl4BXDuXU6hU/+dCF6b+gLJvWaGzuKiQyfDYrm8= dummy debugging key'

    valid_dummy_key_2 = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAYQDmOXORyDk9dZSYxudLF' + \
            '1xEivuixKRVT6OCg7SDySJHVzqFnQkJSXwwcCEF0FdTAA0VaidIpgDhXdj9UFzcKfgo3H' + \
            'f0R5bLAZXn7UQjNWh3M8v+K9cUVIWBukIoLlzs4zE= dummy debugging key 2'
 
    class dummy_user():
        pw_name='toresbe'
        pw_passwd='x'
        pw_uid=1000
        pw_gid=1000
        pw_gecos='Legitimate User With Unfurnished Home'
        pw_dir=None
        pw_shell='/bin/bash'

    def empty_dir(self, username):
        return self.dummy_user

    def setUp(self):
        self.dummy_user.pw_dir = tempfile.mkdtemp()
        pwd.getpwnam = self.empty_dir

    def tearDown(self):
        tmpdir = self.dummy_user.pw_dir
        #print 'Cleaning up, deleting directory ', 
        try:
            os.unlink(tmpdir + '/.ssh/authorized_keys')
        except Exception as e:
            pass

        try:
            os.rmdir(tmpdir + '/.ssh')
        except Exception as e:
            pass
        try:
            os.rmdir(tmpdir)
        except Exception as e:
            pass

    def testConstruction(self):
        f = SSHAuthorizedKeysFile('yada')
        self.assertIsInstance(f, SSHAuthorizedKeysFile)

    def testAddOneValidKey(self):
        f = SSHAuthorizedKeysFile('yada')
        self.assertEqual(len(f.keys), 0)
        f.append(self.valid_dummy_key_1)
        self.assertEqual(len(f.keys), 1)

    def testRefuseDuplicateKey(self):
        f = SSHAuthorizedKeysFile('yada')
        self.assertEqual(len(f.keys), 0)
        f.append(self.valid_dummy_key_1)
        self.assertRaises(ValueError, f.append, self.valid_dummy_key_1)

    def testNewKeysPersist(self):
        f = SSHAuthorizedKeysFile('yada')
        self.assertEqual(len(f.keys), 0)
        f.append(self.valid_dummy_key_1)
        del f
        f = SSHAuthorizedKeysFile('yada')
        self.assertEqual(len(f.keys), 1)

    def testIndexErrorFromBadIndex(self):
        f = SSHAuthorizedKeysFile('yada')
        self.assertRaises(IndexError, f.__getitem__, 1)

    def testCorrectKeyRemoved(self):
        f = SSHAuthorizedKeysFile('yada')
        f.append(self.valid_dummy_key_1)
        f.append(self.valid_dummy_key_2)
        del f[0]
        del f
        f = SSHAuthorizedKeysFile('yada')
        self.assertEqual(len(f.keys), 1)
        self.assertEqual(f[0].keydata, self.valid_dummy_key_2)

    def testKeyRemovalPersists(self):
        f = SSHAuthorizedKeysFile('yada')
        f.append(self.valid_dummy_key_1)
        del f[0]
        del f
        f = SSHAuthorizedKeysFile('yada')
        self.assertEqual(len(f.keys), 0)

    def testCreatesInitialSSHDir(self):
        self.assertIsInstance(SSHAuthorizedKeysFile('yada'), SSHAuthorizedKeysFile)
        self.failUnless(os.path.isdir(self.dummy_user.pw_dir + '/.ssh'))

class SSHAuthorizedKeysBadUsersTest(unittest.TestCase):
    # good to make sure
    def testTrueIsTrue(self):
        self.failUnless(True)

    def testUserNoHome(self):
        class homeless_user():
            pw_name='toresbe'
            pw_passwd='x'
            pw_uid=1000
            pw_gid=1000
            pw_gecos='Legitimate Homeless User'
            pw_dir='/this/really/should/not/exist/on/your/system'
            pw_shell='/bin/bash'

        def no_such_dir(username):
            return homeless_user

        pwd.getpwnam = no_such_dir
        self.assertRaises(ValueError,SSHAuthorizedKeysFile,'dummy_username')

    def testNonexistantUser(self):
        def no_such_user(username):
            raise KeyError
        pwd.getpwnam = no_such_user
        self.assertRaises(KeyError,SSHAuthorizedKeysFile,'dummy_username')

if __name__ == '__main__':
    unittest.main()
