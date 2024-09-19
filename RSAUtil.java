package commons;

import controllers.auth.SecureFront;
import models.Member;
import models.RSAPublicPrivate;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.*;
import java.util.HashMap;
import java.util.Map;

/**
 * RSA加解密及转换成字符串存储和签名及其校验
 * 此方法对电脑CPU性能要求过高，暂停使用
 * 600的并发量时，延迟130秒左右
 *
 * RSA加密速度挺快，解密速度过慢
 * 6K大小的文件加密0s，解密1s
 * 1M的文件加密5s左右，解密4分钟
 * 1G的文件加密1分钟，解密65小时
 *
 * ====================此方法只开放六个对外接口===================慎重使用==============================================
 * 1、getFinalMap()该方法用来生成要保存的密钥对。返回Map<String, String>
 * 2、verify()该方法用来校验签名是否正确。传入数据库中已经加密好的字符串，返回boolean
 * 3、inputToDatabase()该方法用来加密数据并生成可以保存到数据库中的字符串。返回String
 * 4、outputFromDatabase()该方法用来解密保存到数据库中的加密字符串。返回String
 * 5、建立的表字段( id(int 11), user_id(int 11), public_key(varchar 1000), private_key(varchar 2000) )
 * 6、finalInputToDatabase()该方法使用的密钥为配置文件中的固定私钥加密
 * 7、finalOutputFromDatabase()该方法使用的密钥为配置文件中的固定公钥解密
 * ---------------------------------------------------------------------------------------------------------------------
 * 特别说明：
 * 一、1~4方法使用的方法是把密钥对保存到5的表中，即每个用户对应一个密钥对，此方法运用时对CPU损耗过高
 * 二、6和7这俩方法使用的是配置文件中事先配置好的密钥对，用户调用时只起到加解密的作用，不会生成另外的密钥对
 * =====================================================================================================================
 * 1、首先每个用户生成一个唯一对应的公私钥
 * 2、把公私钥用strKey()方法生成对应的字符串存入数据库
 * 3、如果有需要加密的数据，先把数据库中的公私钥字符串取出并根据getPublicKey()和getPrivateKey()方法进行转换成公私钥
 * 4、获取用户要加密的数据字符串，并且把该字符串用strBytes()方法转换成byte数组
 * 5、根据公钥通过encrypt()方法加密第4步转换成的byte数组
 * 6、通过bytesToStore()方法加密第5步来转换加密后的byte数组为最终要存入数据库中的字符串
 * 7、取值：把数据库中存入的字符串取出并且用storeToBytes()方法来解码成加密时的byte数组
 * 8、最终解密：通过getPrivateKey()方法把数据库中的私钥取出并进行解密再通过decrypt()方法把数据解密出来
 * Created by LiZQ on 2016-3-3.
 * Time: 14:00.
 */
public class RSAUtil {

	/**
	 * 根据公钥进行加密
	 * @param publicKey     根据公钥进行加密
	 * @param srcBytes      要加密的字节数组
	 * @return              加密后的值
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	private static byte[] encrypt(PublicKey publicKey, byte[] srcBytes) throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		if (publicKey != null) {
			//Cipher负责完成加密或解密工作，基于RSA
			Cipher cipher = Cipher.getInstance("RSA");
			//根据公钥，对Cipher对象进行初始化
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			return cipher.doFinal(srcBytes);
		}
		return null;
	}

	/**
	 * 根据私钥进行解密
	 * @param privateKey    根据传入的私钥解密
	 * @param srcBytes      要解密的字节数组
	 * @return              解密后的值
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	private static byte[] decrypt(PrivateKey privateKey, byte[] srcBytes) throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		if (privateKey != null) {
			//Cipher负责完成加密或解密工作，基于RSA
			Cipher cipher = Cipher.getInstance("RSA");
			//根据私钥，对Cipher对象进行初始化
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			return cipher.doFinal(srcBytes);
		}
		return null;
	}

	/**
	 * 得到RSA公私钥
	 * @return  公私钥MAP集合
	 */
	private static Map<String, Object> keyMap() throws NoSuchAlgorithmException {
		//KeyPairGenerator类用于生成公钥和私钥对，基于RSA算法生成对象
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
		//初始化密钥对生成器，密钥大小为512位--RSA加密最低要求512的长度
		keyPairGen.initialize(512);
		//生成一个密钥对，保存在keyPair中
		KeyPair keyPair = keyPairGen.generateKeyPair();
		//得到私钥
		PrivateKey privateKey = keyPair.getPrivate();
		//得到公钥
		PublicKey publicKey = keyPair.getPublic();
		Map<String, Object> map = new HashMap<>();
		map.put("privateKey", privateKey);
		map.put("publicKey", publicKey);
		return map;
	}

	/**
	 * 得到密钥字符串
	 * @param key   密钥
	 * @return      返回字符串
	 */
	private static String strKey(Key key) {
		byte[] keyBytes = key.getEncoded();
//		String s = new BASE64Encoder().encode(keyBytes);
		return (new BASE64Encoder()).encodeBuffer(keyBytes);
	}

	/**
	 * 根据字符串获得公钥
	 * @param key   密钥字符串(经过base64编码)
	 * @return      公钥
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	private static PublicKey getPublicKey(String key) throws IOException,NoSuchAlgorithmException, InvalidKeySpecException {
		byte[] keyBytes = new BASE64Decoder().decodeBuffer(key);
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//		RSAPublicKey publicKey = keyFactory.generatePublic(keySpec);
		return keyFactory.generatePublic(keySpec);
	}

	/**
	 * 根据字符串获得私钥
	 * @param key   私钥字符串(经过base64编码)
	 * @return      私钥
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	private static PrivateKey getPrivateKey(String key) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
		byte[] keyBytes = new BASE64Decoder().decodeBuffer(key);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//		PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
		return keyFactory.generatePrivate(keySpec);
	}

	/**
	 * 根据传入的字符串转换成byte数组，等待加密
	 * @param str       等待加密的字符串
	 * @return          转换成的byte数组
	 * @throws UnsupportedEncodingException
	 */
	private static byte[] strBytes(String str) throws UnsupportedEncodingException{

		return str.getBytes("UTF-8");
	}

	/**
	 * 根据加密后的bytes数组生成要存入数据库中的字符串
	 * @param bytes     加密后的字节数组
	 * @return          最终要存入数据库的字符串
	 */
	private static String bytesToStore(byte[] bytes) {

		return new BASE64Encoder().encodeBuffer(bytes);
	}

	/**
	 * 初步分解存入数据库中的加密字符串
	 * @param str       数据库中的加密字符串
	 * @return          加密之前的byte数组
	 * @throws IOException
	 */
	private static byte[] storeToBytes(String str) throws IOException{

		return new BASE64Decoder().decodeBuffer(str);
	}

	/**
	 * 私钥签名
	 * @param data          加密后的数据
	 * @param privateKey    数据库中存的私钥
	 * @return              签名数据
	 */
	private static String sign(byte[] data, String privateKey) {
		try {
			//解密私钥
			byte[] keyBytes = new BASE64Decoder().decodeBuffer(privateKey);
			//构造PKCS8EncodedKeySpec对象
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyBytes);
			//指定加密算法
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			//取私钥匙对象
			PrivateKey privateKey2 = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
			//用私钥对信息生成数字签名
			Signature signature = Signature.getInstance("MD5withRSA");
			signature.initSign(privateKey2);
			signature.update(data);
			return new BASE64Encoder().encodeBuffer(signature.sign());
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * 公钥校验数字签名
	 * 校验的时候说明该密钥对是始终存在的，不需非空校验
	 * @param dataStr       数据库中的已加密数据
	 * @return              校验结果
	 */
	public static boolean verify(String dataStr) {
		try {
//			Member member = SecureFront.getMember();
//			RSAPublicPrivate rpp = RSAPublicPrivate.find(" user = ? ", member).first();
//			String publicKey = rpp.publicKey;
//			String privateKey = rpp.privateKey;
			String publicKey = CommonUtil.PUBLIC_KEY;
			String privateKey = CommonUtil.PRIVATE_KEY;
			//初步解密加密数据
			byte[] data = new BASE64Decoder().decodeBuffer(dataStr);
			//获取签名
			String sign = sign(data, privateKey);
			//解密公钥
			byte[] keyBytes = new BASE64Decoder().decodeBuffer(publicKey);
			//构造X509EncodedKeySpec对象
			X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyBytes);
			//指定加密算法
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			//取公钥匙对象
			PublicKey publicKey2 = keyFactory.generatePublic(x509EncodedKeySpec);

			Signature signature = Signature.getInstance("MD5withRSA");
			signature.initVerify(publicKey2);
			signature.update(data);
			//验证签名是否正常
			return signature.verify(new BASE64Decoder().decodeBuffer(sign));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}

	/**
	 * 获取要保存到数据库中的加密字符串
	 * 如果加密过程中获取不到用户的密钥对则生成新的密钥对
	 * 此方法用来生成保存到数据库中的密钥对时的加密
	 * @param str       要保存的字符串
	 * @return          加密后的字符串
	 */
	public static String inputToDatabase(String str) {
		try {
			Member member = SecureFront.getMember();
			Long rppCount = RSAPublicPrivate.count("user = ?", member);
			if (rppCount.intValue() == 0) {
				//保存当前用户的密钥
				RSAPublicPrivate rsa = new RSAPublicPrivate();
				rsa.user = member;
				Map<String, String> map = getFinalMap();
				rsa.publicKey = map.get("publicKey");
				rsa.privateKey = map.get("privateKey");
				rsa._save();
			}
			RSAPublicPrivate rpp = RSAPublicPrivate.find(" user = ? ", member).first();
			PublicKey publicKey = getPublicKey(rpp.publicKey);
			byte[] bytes = strBytes(str);
			byte[] encrypt = encrypt(publicKey, bytes);
			String inputStr = bytesToStore(encrypt);
			return InfoUtil.cleanSpaces(inputStr);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * 从数据库中获取加密后的字符串并反解密
	 * 解密过程不能生成新的密钥对，如果加密过程中生成的密钥对丢失则解密失败，数据永久性丢失
	 * 此方法用来处理保存到数据库中密钥对的数据解密
	 * @param str       加密后的数据库字符串
	 * @return          解密后的字符串
	 */
	public static String outputFromDatabase(String str) {
		try {
			Member member = SecureFront.getMember();
			RSAPublicPrivate rpp = RSAPublicPrivate.find(" user = ? ", member).first();
			PrivateKey privateKey = getPrivateKey(rpp.privateKey);
			byte[] bytes = storeToBytes(str);
			byte[] decrypt = decrypt(privateKey, bytes);
			return new String(decrypt);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * 获取需要保存到数据库中的密钥对
	 * @return      字符串类型的MAP集合
	 */
	public static Map<String, String> getFinalMap() {
		try {
			Map<String, String> strMap = new HashMap<>();
			Map<String, Object> map = keyMap();
			PublicKey publicKey = (PublicKey)map.get("publicKey");
			PrivateKey privateKey = (PrivateKey)map.get("privateKey");
			String pubKey = strKey(publicKey);
			String priKey = strKey(privateKey);
			strMap.put("publicKey", InfoUtil.cleanSpaces(pubKey));
			strMap.put("privateKey", InfoUtil.cleanSpaces(priKey));
			return strMap;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * 通过配置文件中的密钥对对数据进行加密
	 * @param str       要加密的数据
	 * @return          加密后的数据
	 */
	public static String finalInputToDatabase(String str) {
		try {
			PublicKey publicKey = getPublicKey(CommonUtil.PUBLIC_KEY);
			byte[] bytes = strBytes(str);
			byte[] encrypt = encrypt(publicKey, bytes);
			String inputStr = bytesToStore(encrypt);
			return InfoUtil.cleanSpaces(inputStr);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * 通过配置文件中的密钥对对数据进行解密
	 * @param str       要解密的数据
	 * @return          解密后的数据
	 */
	public static String finalOutputFromDatabase(String str) {
		try {
			PrivateKey privateKey = getPrivateKey(CommonUtil.PRIVATE_KEY);
			byte[] bytes = storeToBytes(str);
			byte[] decrypt = decrypt(privateKey, bytes);
			return new String(decrypt);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
}