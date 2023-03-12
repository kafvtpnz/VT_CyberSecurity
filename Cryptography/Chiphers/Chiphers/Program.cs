
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;
using System.Text;
class Program
{
    public static void Main(string[] args)
    {
        HashAlgorithm();
        DiffiHelman();
        Elgamal();
        RsaBouncyCastle();
        RSA();
        BlowFish();
        AES();
    }

    public static void AES()
    {
        Console.Write("Input string to encrypt: ");
        var text = Console.ReadLine();
        // создаём шифр
        using System.Security.Cryptography.Aes aes = System.Security.Cryptography.Aes.Create();
        // генерируем ключ или используем свой ключ с помощью aes.Key = my_key; aes.IV = my_iv
        aes.GenerateKey();
        // зашифровываем данные с помощью режима сцепления блоков CBC и случайного числа(aes.IV)
        var ecryptedArray = aes.EncryptCbc(Encoding.UTF8.GetBytes(text), aes.IV);
        var encryptedText = Encoding.UTF8.GetString(ecryptedArray);
        // расшифровываем данные
        var decryptedText = Encoding.UTF8.GetString(aes.DecryptCbc(ecryptedArray, aes.IV));

        Console.WriteLine($"Open text: {text}");
        Console.Write("Key: ");
        foreach (var bt in aes.Key) Console.Write($"{bt.ToString()} ");
        Console.WriteLine();
        Console.Write("IV(initialization vector): ");
        foreach (var bt in aes.IV) Console.Write($"{bt.ToString()} ");
        Console.WriteLine();
        Console.WriteLine($"Encrypred text: {encryptedText}");
        Console.WriteLine($"Decrypted text: {decryptedText}");
    }

    public static void BlowFish()
    {
        string text = "Привет, я читал канал VT_InfoSecurity";
        var key = Encoding.UTF8.GetBytes("Я есть ключ");
        // Создаём шифр и получаем размер блока. Размер блока покажет
        // Количество шифруемых байт за раз
        BlowfishEngine engine = new BlowfishEngine();
        int blockSize = engine.GetBlockSize(); // = 8 байт
        // Подумайте, почему выбрали массивы длинной 1024?
        byte[] openText = new byte[1024];
        byte[] encryptedBuffer = new byte[1024];
        byte[] decryptedBuffer = new byte[1024];
        // Копируем текст в массив байт (занимает 54 байта)
        Encoding.UTF8.GetBytes(text).CopyTo(openText, 0);
        // Создаём ключ и инициализируем шифр в режиме шифрования
        var keyParam = new KeyParameter(key);
        engine.Init(true, keyParam);
        // Разбиваем openText на блоки,длинна которых равна длинне ключа
        // Начинаем шифровать данные с первого блока
        // Когда блок успешно зашифрован, ProcessBlock возвращает количество зашифрованных байт
        // На каждой итерации делаем смещение относительно начального положения на количество зашифрованных байт
        // Шифруем, пока все блоки не будут зашифрованы
        int i = 0;
        while (i < openText.Length)
        {
            i += engine.ProcessBlock(openText, i, encryptedBuffer, i);
        }
        // Задаём режим дешифрования
        engine.Init(false, keyParam);
        // Блоками дешифруем
        i = 0;
        while (i < encryptedBuffer.Length)
        {
            i += engine.ProcessBlock(encryptedBuffer, i, decryptedBuffer, i);
        }
        var decryptedText = Encoding.UTF8.GetString(encryptedBuffer);
    }

    public static void RSA()
    {
        string text = "Привет, я читаю канал VT_InfoSecurity";
        byte[] openText = Encoding.UTF8.GetBytes(text);
        // Моделируем ситуацию отправитель - получатель
        // Создаём "отправителя"
        using System.Security.Cryptography.RSACryptoServiceProvider rsaProvider_Sender = new RSACryptoServiceProvider();
        // Создаём "получателя"
        using System.Security.Cryptography.RSACryptoServiceProvider rsaProvider_Receiver = new RSACryptoServiceProvider();
        // Создаём "злоумышленника"
        using System.Security.Cryptography.RSACryptoServiceProvider rsaProvider_Attacker = new RSACryptoServiceProvider();
        // получатель сообщает отправителю свой публичный ключ
        var publicKey = rsaProvider_Receiver.ToXmlString(false);
        rsaProvider_Sender.FromXmlString(publicKey);
        // Отправитель шифрует данные с помощью публичного ключа получателя
        var sendData = rsaProvider_Sender.Encrypt(openText, false);
        var senderText = Encoding.UTF8.GetString(sendData);
        try
        {
            // Злоумышленник увидел открытый ключ
            // Теперь он будет пытаться с помощью открытого ключа расшифровать шифртекст
            // Если бы это было симметричное шифрование, то у него бы всё получилось
            // но у нас асиметричное
            rsaProvider_Attacker.FromXmlString(publicKey);
            var sender_decrypt_data = rsaProvider_Attacker.Decrypt(sendData, false);
        }
        catch (CryptographicException ex)
        {
            Console.WriteLine(ex.Message);
        }
        // Получатель расшифровывает данные своим публичным ключом
        var receiveData = rsaProvider_Receiver.Decrypt(sendData, false);
        var receivedText = Encoding.UTF8.GetString(receiveData);
    }

    public static void RsaBouncyCastle()
    {
        var text = "Привет, я читаю канал VT_InfoSecurity";
        // получаем массив байт для шифрования
        var openText = Encoding.UTF8.GetBytes(text);
        // создаём шифр RSA
        RsaEngine rsaEngine = new RsaEngine();
        // создаём защищённый генератор случайных чисел
        var random = new SecureRandom();
        // создаём генератор пар - открытый ключ - закрытый ключ
        // при этом указываем, что числа для генерации будут идти из защищённого генератора
        // длинна ключа будет составлять 128 байт(1024 бита)
        var generationParam = new KeyGenerationParameters(random, 1024);
        var rsaKeyGenerator = new RsaKeyPairGenerator();
        rsaKeyGenerator.Init(generationParam);
        // получаем пару открытый-закрытый ключ
        var result = rsaKeyGenerator.GenerateKeyPair();
        // задаём режим шифрования - указываем открытый ключ (зашифровываем данные)
        rsaEngine.Init(true, result.Public);
        // для текущего режима получаем шифртекст
        var encryptedData = rsaEngine.ProcessBlock(openText, 0, openText.Length);
        // задаём режим шифрования - указываем закрытый ключ (расшифровываем данные)
        rsaEngine.Init(false, result.Private);
        // получаем открытый текст
        var decryptedData = rsaEngine.ProcessBlock(encryptedData, 0, encryptedData.Length);
        // получаем исходную строку
        var decryptedText = Encoding.UTF8.GetString(decryptedData);
    }

    public static void Elgamal()
    {
        var text = "Привет, я читаю канал VT_InfoSecurity";
        // получаем массив байт для шифрования
        var openText = Encoding.UTF8.GetBytes(text);

        ElGamalEngine elGamalEngine = new ElGamalEngine();
        SecureRandom secureRandom = new SecureRandom();
        ElGamalParametersGenerator generator = new ElGamalParametersGenerator();
        generator.Init(1024, 0, secureRandom);
        //ElGamalParameters elGamalParameters = new ElGamalParameters(secureRandom.NextInt64(),secureRandom.NextInt64());
        ElGamalKeyGenerationParameters elGamalKeyGenerationParameters = new ElGamalKeyGenerationParameters(secureRandom, generator.GenerateParameters());
        ElGamalKeyPairGenerator keyPairGenerator = new ElGamalKeyPairGenerator();
        keyPairGenerator.Init(elGamalKeyGenerationParameters);
        var keyPair = keyPairGenerator.GenerateKeyPair();
        elGamalEngine.Init(true, keyPair.Public);
        var size = elGamalEngine.GetInputBlockSize();
        var encryptedData = elGamalEngine.ProcessBlock(openText,0,openText.Length);
        var ecnryptedText = Encoding.UTF8.GetString(encryptedData);

        elGamalEngine.Init(false,keyPair.Private);
        var decryptedData = elGamalEngine.ProcessBlock(encryptedData,0,encryptedData.Length);
        var decryptedText = Encoding.UTF8.GetString(decryptedData);
    }

    public static void DiffiHelman()
    {
        using System.Security.Cryptography.ECDiffieHellmanCng diffieHellman = new ECDiffieHellmanCng();
        diffieHellman.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
        diffieHellman.HashAlgorithm = CngAlgorithm.Sha256;

        using ECDiffieHellmanCng bob = new ECDiffieHellmanCng();
        bob.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
        bob.HashAlgorithm = CngAlgorithm.Sha256;

        var aliceKey = diffieHellman.DeriveKeyMaterial(bob.PublicKey);
        var bobKey = bob.DeriveKeyMaterial(diffieHellman.PublicKey);

        Console.WriteLine($"Bob secret key: {string.Join("", bobKey.Select(bt=> $"{bt.ToString()} "))}");
        Console.WriteLine($"Alice secret key: {string.Join("", aliceKey.Select(bt => $"{bt.ToString()} "))}");
    }

    public static void HashAlgorithm()
    {
        string text = "Я читаю канал VT_CyberSecurity";
        var md5 = System.Security.Cryptography.MD5.Create();
        var sha1 = System.Security.Cryptography.SHA1.Create();
        var sha256 = System.Security.Cryptography.SHA256.Create();
        var array = Encoding.UTF8.GetBytes(text);
        Console.WriteLine($"Base text: {text}");
        Console.WriteLine($"MD5: {string.Join(" ", md5.ComputeHash(array))} - Length: 16 byte");
        Console.WriteLine($"SHA1: {string.Join(" ", sha1.ComputeHash(array))} - Length: 20 byte");
        Console.WriteLine($"SHA256: {string.Join(" ", sha256.ComputeHash(array))} - Length: 32 byte");
        Org.BouncyCastle.Crypto.Digests.MD5Digest mD5Digest = new Org.BouncyCastle.Crypto.Digests.MD5Digest();
        mD5Digest.BlockUpdate(array, 0, array.Length);
        var output = new byte[mD5Digest.GetDigestSize()];
        mD5Digest.DoFinal(output);
        Console.WriteLine($"BouncyCastle MD5: {string.Join(" ", output.Length)}");
    }


}


