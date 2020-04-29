# ~*~ coding: utf-8 ~*~
import base64

import os
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
try:
    from .utils import get_logger
    logger = get_logger(__file__)
except Exception:
    import logging
    logger = logging.getLogger(__file__)
    logger.debug = print


class AESAlgorithm:

    AES_KEY = os.environ.get('AUTH_OPENID_GRANT_TYPE_PASSWORD_AES_KEY', 'a04f4883d181a239')
    AES_PADDING_STYLE = os.environ.get('AUTH_OPENID_GRANT_TYPE_PASSWORD_AES_KEY', 'pkcs7')
    AES_MODE = os.environ.get('AUTH_OPENID_GRANT_TYPE_PASSWORD_AES_MODE', 'MODE_ECB')
    AES_IV = os.environ.get('AUTH_OPENID_GRANT_TYPE_PASSWORD_AES_IV', None)
    AES_MODE = getattr(AES, AES_MODE, None)
    AES_BLOCK_SIZE = os.environ.get('AUTH_OPENID_GRANT_TYPE_PASSWORD_AES_BLOCK_SIZE', AES.block_size)

    """
        AES
        加密模式: ECB
        填充：pkcs5padding
        数据块：128 位
        密码：a04f4883d181a239
        偏移量：空的
        输出 ：base64
        字符集：utf8
    """

    @classmethod
    def new_aes(cls):
        kwargs = {
            'key': cls.AES_KEY.encode('utf-8'),
            'mode': cls.AES_MODE
        }
        if cls.AES_IV is not None:
            kwargs.update({'iv': cls.AES_IV})
        aes = AES.new(**kwargs)
        return aes

    @classmethod
    def decrypt(cls, source):
        source_bytes = base64.b64decode(source)
        aes = cls.new_aes()
        source_bytes = aes.decrypt(source_bytes)
        source_bytes = unpad(source_bytes, cls.AES_BLOCK_SIZE, style=cls.AES_PADDING_STYLE)
        source_decrypt = source_bytes.decode('utf-8')
        return source_decrypt

    @classmethod
    def encrypt(cls, plain):
        plain_bytes = plain.encode('utf-8')
        plain_bytes = pad(plain_bytes, cls.AES_BLOCK_SIZE, style=cls.AES_PADDING_STYLE)
        aes = cls.new_aes()
        plain_bytes = aes.encrypt(plain_bytes)
        plain_encrypt = base64.b64encode(plain_bytes).decode()
        return plain_encrypt

    @classmethod
    def test(cls, text="JumpServer@FIT2CLOUD#!@*>(:-:test-text"):
        print('Test AES')
        for c in dir(cls):
            if c.startswith('AES_'):
                print('CONFIG: {} => {}'.format(c, getattr(cls, c)))
        print("Origin text: {}".format(text))
        encrypted = cls.encrypt(text)
        print("encrypted: {}".format(encrypted))
        decrypted = cls.decrypt(encrypted)
        print("decrypted: {}".format(decrypted))


USE_AES = os.environ.get('AUTH_OPENID_GRANT_TYPE_PASSWORD_USE_AES') != 0


def encrypt_password(password, alg='aes'):
    if alg == 'aes' and USE_AES:
        encrypted_password = AESAlgorithm.encrypt(plain=password)
        logger.debug(
            "Get encrypted password: Algorithm: {} => source password: {} => encrypt_password: {}"
            "".format(alg, password, encrypted_password)
        )
        return encrypted_password
    else:
        logger.debug(
            "Not encrypt, because Algorithm: {}, => USE_AES: {} => source password: {}"
            "".format(alg, USE_AES, password)
        )
        return password


if __name__ == '__main__':
    AESAlgorithm().test()
    encrypt_password('JumpServer@FIT2CLOUD#!@*>(:-:test-text')

