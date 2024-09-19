package commons;

import controllers.auth.SecureFront;
import models.Member;
import models.RSAPublicPrivate;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.io.IOException;
import java.security.SecureRandom;

/**
 * 此类是DES加解密的专用类
 * 其中KEY密钥必须是8的倍数，
 * inputToDatabase()方法中要保存到数据库中的KEY为8的1~10倍数中的随机数
 * inputToDatabase和outputFromDatabase这俩方法取值为数据库中保存的KEY
 * finalInputToDatabase和finalOutputFromDatabase这俩方法取的配置文件中的KEY
 * Created by LiZQ on 2016-3-7.
 * Time: 17:21.
 */
public class DESUtil {

	/**
	 * 加密操作
	 * @param bytes     要加密的字节数组
	 * @param key       密钥
	 * @return          加密后的字节数组
	 */
	private static byte[] encrypt(byte[] bytes, String key) {
		try {
			SecureRandom random = new SecureRandom();
			DESKeySpec desKeySpec = new DESKeySpec(key.getBytes());
			// 创建密钥工厂，然后用它把DESKeySpec转换成
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
			SecretKey secretKey = keyFactory.generateSecret(desKeySpec);
			// Cipher对象实际完成加密操作
			Cipher cipher = Cipher.getInstance("DES");
			// 用密匙初始化Cipher对象
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, random);
			// 现在，获取数据并加密
			// 正式执行加密操作
			return cipher.doFinal(bytes);
		} catch (Throwable e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * 解密
	 * @param src       加密后的字节数组
	 * @param key       密钥
	 * @return          解密后的字节数组
	 */
	private static byte[] decrypt(byte[] src, String key) {
		try {
			// DES算法要求有一个可信任的随机数源
			SecureRandom random = new SecureRandom();
			// 创建一个DESKeySpec对象
			DESKeySpec desKey = new DESKeySpec(key.getBytes());
			// 创建一个密匙工厂
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
			// 将DESKeySpec对象转换成SecretKey对象
			SecretKey secretKey = keyFactory.generateSecret(desKey);
			// Cipher对象实际完成解密操作
			Cipher cipher = Cipher.getInstance("DES");
			// 用密匙初始化Cipher对象
			cipher.init(Cipher.DECRYPT_MODE, secretKey, random);
			// 真正开始解密操作
			return cipher.doFinal(src);
		} catch (Throwable e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * 最终加密算法，对外开放的接口
	 * @param str       要加密的字符串
	 * @return          加密后可以存放到数据库中的字符串
	 */
	public static String inputToDatabase(String str) {
		Member member = SecureFront.getMember();
		Long count = RSAPublicPrivate.count(" user = ? ", member);
		if (count.intValue() == 0) {
			RSAPublicPrivate rpp = new RSAPublicPrivate();
			rpp.desKey = InfoUtil.cleanSpaces(CommonUtility.getRandomPwCode(CommonUtility.getSomeIntMultiple(8)));
			rpp.user = SecureFront.getMember();
			rpp._save();
		}
		RSAPublicPrivate rpp = RSAPublicPrivate.find(" user = ?", member).first();
		byte[] bytes = encrypt(str.getBytes(), rpp.desKey);
		return InfoUtil.cleanSpaces(new BASE64Encoder().encodeBuffer(bytes));
	}

	/**
	 * 解密的最终算法，对外开放的接口
	 * @param str       加密后的字符串
	 * @return          解密后的字符串
	 */
	public static String outputFromDatabase(String str) {
		try {
			RSAPublicPrivate rpp = RSAPublicPrivate.find(" user = ?", SecureFront.getMember()).first();
			byte[] bytes = new BASE64Decoder().decodeBuffer(str);
			byte[] decrypt = decrypt(bytes, rpp.desKey);
			return new String(decrypt);
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * 通过配置文件中的密钥进行加密
	 * @param str       要加密的数据
	 * @return          加密后的数据
	 */
	public static String finalInputToDatabase(String str) {
		try {
			byte[] bytes = encrypt(str.getBytes(), CommonUtil.DES_KEY);
			return InfoUtil.cleanSpaces(new BASE64Encoder().encodeBuffer(bytes));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * 通过配置文件中的密钥进行解密
	 * @param str       要解密的数据
	 * @return          解密后的数据
	 */
	public static String finalOutputFromDatabase(String str) {
		try {
			byte[] bytes = new BASE64Decoder().decodeBuffer(str);
			byte[] decrypt = decrypt(bytes, CommonUtil.DES_KEY);
			return new String(decrypt);
		}catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
}
