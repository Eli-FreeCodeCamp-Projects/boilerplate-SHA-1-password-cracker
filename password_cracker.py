import hashlib
from hashlib import pbkdf2_hmac
import os
import inspect
from ve_utils.utype import UType as Ut

"""Hash crack helper class"""
class HashCracker:

    @staticmethod
    def dict_reader(file_path: str):
        """Read a dictionary line by line"""
        if os.path.isfile(file_path):
            with open(file_path, "r") as content:
                for line in content:
                    yield line.replace(' ', '').replace('\n', '').replace('\r', '')

    @staticmethod
    def hash_test(hash_crack: str, password: bytes) -> bool:
        """Test if hash is equal to password"""
        result = False
        hash_test = hashlib.sha1(password).hexdigest()
        if hash_test == hash_crack:
            result = True
        return result

    @staticmethod
    def hash_salted_test(hash_crack: str, password: bytes, hash_dict: str) -> tuple:
        """Test if hash is equal to password with salt before or after"""
        for salt in HashCracker.dict_reader(hash_dict):
            hashed = b"%s%s" % (salt.encode('utf-8'), password)
            hash_test = hashlib.sha1(hashed).hexdigest()
            if hash_test == hash_crack:
                return (True, salt, 'before')
            hashed = b"%s%s" % (password, salt.encode('utf-8'))
            hash_test = hashlib.sha1(hashed).hexdigest()
            if hash_test == hash_crack:
                return (True, salt, 'after')
        return (False, None, None)
        

    @staticmethod
    def hash_compare(hash_crack: str,
                     pass_dict: str,
                     hash_dict: str or None = None
                     ) -> str or tuple:
        """Brute force a hash crack with dictionaries."""
        for password in HashCracker.dict_reader(pass_dict):
            b_password = password.encode('utf-8')
            
            if HashCracker.hash_test(hash_crack, b_password):
                return (hash_crack, password, None, None)
            if hash_dict is not None:
                if password == "q1w2e3r4t5":
                    a = 2
                (isMatch, salt, salt_position) =  HashCracker.hash_salted_test(hash_crack, b_password, hash_dict)
                if isMatch is True:
                    return (hash_crack, password, salt, salt_position)
        
        return "PASSWORD NOT IN DATABASE"
                

def crack_sha1_hash(hash_crack, use_salts=False):
    """Brute force a hash crack with dictionaries."""
    current_script_path = os.path.dirname(
        os.path.abspath(inspect.getfile(inspect.currentframe()))
    )
    pass_dict = os.path.join(current_script_path, "top-10000-passwords.txt")
    if use_salts is True:
        hash_dict = os.path.join(current_script_path, "known-salts.txt")
    else:
        hash_dict = None
    crack = HashCracker.hash_compare(hash_crack, pass_dict, hash_dict)

    if Ut.is_tuple(crack):
        result = crack[1]
    else:
        result = crack
    return result
