using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Net.Sockets;
using System.Threading;
using System.Text.Json.Serialization;
using System.Text.Json;
using System.Security.Cryptography;

namespace SocketClient
{
    public class ChatMessage
    {
        public string Name { get; set; }
        public string Message { get; set; }
        public byte[] Exp { get; set; }
        public byte[] Mod { get; set; }
    }
    public class Program
    {
        public static byte[] EncryptMessage(byte[] broadcastBytes, RSAParameters key)
        {
            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {
                RSA.ImportParameters(key);

                return RSA.Encrypt(broadcastBytes, false);
            }
        }
        public static string SerializeMessage(ChatMessage m)
        {
            return JsonSerializer.Serialize(m);
        }
        public static ChatMessage DeserializeMessage(string s)
        {
            return JsonSerializer.Deserialize<ChatMessage>(s);
        }
        static TcpClient clientSocket = new TcpClient();
        static NetworkStream serverStream = null;
        static readonly RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048);
        static string readData = null;
        static RSAParameters serverKey;
        static AesManaged aes = new AesManaged();
        static void Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.InputEncoding = Encoding.UTF8;
            aes.GenerateKey();
            Console.WriteLine("Write name: ");
            connect(Console.ReadLine());
            while (true)
            {
                SendEncrypted(Console.ReadLine());
            }
        }
        public static bool CheckIfTrue(bool booleanToEvaluate)
        {
            if (booleanToEvaluate == true)
            {
                return true;
            }
            else
            {
                return false;
            }
        }
        static void getMessage(TcpClient client)
        {
            while (client.Connected)
            {
                NetworkStream serverStream = client.GetStream();
                byte[] inStream = new byte[client.ReceiveBufferSize];
                int bytes_read = serverStream.Read(inStream, 0, inStream.Length);
                if (bytes_read > 0)
                {
                    Array.Resize(ref inStream, bytes_read);
                    byte[] decrypted = rsa.Decrypt(inStream, false);
                    string returndata = Encoding.UTF8.GetString(decrypted);
                    ChatMessage m = DeserializeMessage(returndata);
                    msg(m.Message);
                }
            }
        }
        static void msg(string s)
        {
            Console.WriteLine("\n>> " + s);
        }
        static void Send(NetworkStream stream, byte[] bytes)
        {
            stream.Write(bytes, 0, bytes.Length);
            stream.Flush();
        }
        static void connect(string name)
        {
            //clientSocket.Connect("127.0.0.1", 8888);
            clientSocket.Connect("172.16.21.31", 1337);
            serverStream = clientSocket.GetStream();
            RSAParameters para = rsa.ExportParameters(false);
            ChatMessage m = new ChatMessage
            {
                Name = name,
                Mod = para.Modulus,
                Exp = para.Exponent,
            };
            byte[] outStream = Encoding.UTF8.GetBytes(SerializeMessage(m));
            Send(serverStream, outStream);
            msg("Connected to NYP Chat Server ...");

            serverStream = clientSocket.GetStream();
            int buffSize = clientSocket.ReceiveBufferSize;
            byte[] inStream = new byte[buffSize];
            int bytes_read = serverStream.Read(inStream, 0, inStream.Length);

            string returndata = Encoding.UTF8.GetString(inStream, 0, bytes_read);
            ChatMessage mess = DeserializeMessage(returndata);
            serverKey = new RSAParameters { Modulus = mess.Mod, Exponent = mess.Exp };

            Thread ctThread = new Thread(() => getMessage(clientSocket));
            ctThread.Start();
        }

        static void SendEncrypted(string message)
        {
            // Send text
            ChatMessage m = new ChatMessage
            {
                Message = message,
            };
            byte[] outStream = Encoding.UTF8.GetBytes(SerializeMessage(m));
            byte[] encrypted = EncryptMessage(outStream, serverKey);
            Send(serverStream, encrypted);
        }
    }
}