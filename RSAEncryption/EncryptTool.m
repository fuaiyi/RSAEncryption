//
//  EncryptTool.m
//  demo
//
//  Created by gaofu on 2017/3/20.
//  Copyright © 2017年 siruijk. All rights reserved.
//
//  Abstract:加密相关工具类

#import "EncryptTool.h"
#import <openssl/pem.h>
#import <GTMBase64.h>
#import<CommonCrypto/CommonDigest.h>

typedef NS_ENUM(NSUInteger, RSAPaddingType)
{
    eRSAPaddingTypeNone      = RSA_NO_PADDING,
    eRSAPaddingTypePKCS1     = RSA_PKCS1_PADDING,
    eRSAPaddingTypeSSLV23    = RSA_SSLV23_PADDING
};

@implementation EncryptTool
{
    RSA *_publicRSA;//公钥的RAS
    RSA *_privateRSA;//私钥的RAS
}


+ (id)shareInstance
{
    static EncryptTool* encryptTool = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        encryptTool = [EncryptTool new];
    });
    return encryptTool;
}




/********************** key的格式化和处理(与加密无关,用来快速处理key)  START  **********************/

//0.1存放本地沙河路径
+(NSString*)RSAKeyFillePath:(KeyType)type
{
    NSString *keyFileName = @[
                              @"public_key.pem",
                              @"private_key.pem"
                              ][type];
    
    return [[NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) lastObject] stringByAppendingPathComponent:keyFileName];
}


//0.2格式化key
+ (NSString *)formattKey:(NSString *)key
{
    if (key == nil) return @"";
    
    NSInteger count = key.length / 64;
    NSMutableString *formattKey = key.mutableCopy;
    for (int i = 0; i < count; i ++)
    {
        [formattKey insertString:@"\n" atIndex:64 + (64 + 1) * i];
    }
    return formattKey == nil ? @"" : formattKey;
}

//0.3写入key文件
+ (BOOL)writeKey:(NSString *)key type:(KeyType)type;
{

    NSString*keyPath = [self RSAKeyFillePath:type];
    
    if ([[NSFileManager defaultManager] fileExistsAtPath:keyPath])
    {
        return YES;
    }
    
    NSString *formattKey = [self formattKey:key];
    
    NSString *keyStr;
    switch (type)
    {
        case eKeyTypePublic:
        {
            keyStr = [NSString stringWithFormat:@"-----BEGIN PUBLIC KEY-----\n%@\n-----END PUBLIC KEY-----",formattKey];
            break;
        }
        case eKeyTypePrivate:
        {
            keyStr = [NSString stringWithFormat:@"-----BEGIN RSA PRIVATE KEY-----\n%@\n-----END RSA PRIVATE KEY-----",formattKey];
            break;
        }
        default:
        {
            return NO;
            
        }
    }
    NSLog(@"格式话处理过的key:\n%@\n",keyStr);
    NSError *error = nil;
    return [keyStr writeToFile:keyPath atomically:YES encoding:NSASCIIStringEncoding error:&error];
}



/********************** key的格式化和处理(与加密无关)  END  **********************/





//1.导入key为RSA结构体对象
- (BOOL)importRSAKey:(KeyType)type
{
    
//    这里是从项目中读取公钥和私钥,你也可以把公钥和私钥存入沙河中,从沙河中读取
    
    switch (type)
    {
        case eKeyTypePublic:
        {
            FILE *file = fopen([[[NSBundle mainBundle] pathForResource:@"public_key.pem" ofType:nil] UTF8String], "rb");
            if (file == NULL) return NO;
            _publicRSA = PEM_read_RSA_PUBKEY(file, NULL, NULL, NULL);
            assert(_publicRSA != nil);
            fclose(file);
            return (_publicRSA != NULL) ? YES : NO;
        }
        case eKeyTypePrivate:
        {
            FILE *file = fopen([[[NSBundle mainBundle] pathForResource:@"private_key.pem" ofType:nil] UTF8String], "rb");
            if (file == NULL) return NO;
            _privateRSA = PEM_read_RSAPrivateKey(file, NULL, NULL, NULL);
            assert(_privateRSA != NULL);
            fclose(file);
            return (_privateRSA != NULL) ? YES : NO;
        }
        default:
        {
            return NO;
        }
    }
}

//2.1加密处理
- (NSData *)encryptToData:(NSString*)content type:(KeyType)type
{
    
    if([self RSAWithType:type] == NULL)
    {
        if (![self importRSAKey:type]) return nil;
    }
    
    RSA *rsa = [self RSAWithType:type];
    
    int status = 0;
    int length  = (int)content.length;
    unsigned char input[length + 1];
    bzero(input, length + 1);
    
    for (int i = 0; i < length; i++)
    {
        input[i] = [content characterAtIndex:i];
    }
    
    NSInteger  flen = [self getBlockSize:eRSAPaddingTypePKCS1 type:type];
    char *encryptData = (char*)malloc(flen);
    bzero(encryptData, flen);
    
    switch (type)
    {
        case eKeyTypePublic:
            status = RSA_public_encrypt(length, (unsigned char*)input, (unsigned char*)encryptData, rsa, eRSAPaddingTypePKCS1);
            break;
            
        default:
            status = RSA_private_encrypt(length, (unsigned char*)input, (unsigned char*)encryptData, rsa, eRSAPaddingTypePKCS1);
            break;
    }
    
    if (status)
    {
        NSData *returnData = [NSData dataWithBytes:encryptData length:status];
        free(encryptData);
        encryptData = NULL;
        return returnData;
    }
    
    free(encryptData);
    encryptData = NULL;
    
    return nil;
}

//2.2解密处理
- (NSString *)decryptToData:(NSString*)content type:(KeyType)type
{
    
    if([self RSAWithType:type] == NULL)
    {
        if (![self importRSAKey:type]) return nil;
    }
    
    RSA *rsa = [self RSAWithType:type];
    int status;
    NSData *data = [content base64Decode];
    int length = (int)data.length;
    
    NSInteger flen = [self getBlockSize:eRSAPaddingTypePKCS1 type:type];
    char *decryptData = (char*)malloc(flen);
    bzero(decryptData, flen);
    
    switch (type)
    {
        case eKeyTypePublic:
            status = RSA_public_decrypt(length, (unsigned char*)[data bytes], (unsigned char*)decryptData, rsa, eRSAPaddingTypePKCS1);
            break;
            
        default:
            status = RSA_private_decrypt(length, (unsigned char*)[data bytes], (unsigned char*)decryptData, rsa, eRSAPaddingTypePKCS1);
            break;
    }
    
    if (status)
    {
        NSMutableString *decryptString = [[NSMutableString alloc] initWithBytes:decryptData length:strlen(decryptData) encoding:NSASCIIStringEncoding];
        free(decryptData);
        decryptData = NULL;
        return decryptString;
    }
    
    free(decryptData);
    decryptData = NULL;
    
    return nil;
}


//3.1实现中文兼容和分段加密
- (NSString *)encrypt:(NSString *)content type:(KeyType)type
{
    content = content.URLEncode;
    NSMutableString *encryptContent = @"".mutableCopy;
    for (NSInteger i = 0; i < ceilf(content.length / 117.0); i ++)
    {
        NSString *subStr = [content substringWithRange:NSMakeRange(i * 117, MIN(117, content.length - i * 117))];
        NSString *encryptSubStr = [[self encryptToData:subStr type:type] base64Encode];
        [encryptContent appendString:encryptSubStr];
    }
    return encryptContent;
}

//3.2实现中文兼容和分段解密
- (NSString *)decrypt:(NSString *)content type:(KeyType)type
{
    NSMutableString *decryptResult = @"".mutableCopy;
    for (NSInteger i = 0; i < ceilf(content.length / 172); i ++)
    {
        NSString *subStr = [content substringWithRange:NSMakeRange(i * 172, 172)];
        NSString *decryptSubStr = [self decryptToData:subStr type:type];
        NSString *decryptStr = decryptSubStr.length <= 117 ? decryptSubStr : [decryptSubStr substringToIndex:117];
        [decryptResult appendString:decryptStr];
    }
    
    return decryptResult.URLDecode;
}




//长度获取
- (int)getBlockSize:(RSAPaddingType)type type:(KeyType)keyType
{
    int len = RSA_size([self RSAWithType:keyType]);
    
    if (type != eRSAPaddingTypeNone)
    {
        len -= 11;
    }
    
    return len;
}


//根据类型获取对应的RSA
-(RSA*)RSAWithType:(KeyType)type
{
    switch (type)
    {
        case eKeyTypePublic:
        {
            return _publicRSA;
        }
        case eKeyTypePrivate:
        {
            return _privateRSA;
        }
        default:
        {
            return nil;
        }
    }
}

@end






@implementation NSString (Encode)

- (NSData*)base64Encode
{
    NSData *data = [self dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:YES];
    data = [GTMBase64 encodeData:data];
    return data;
}

- (NSData*)base64Decode
{
    NSData *data = [self dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:YES];
    data = [GTMBase64 decodeData:data];
    return data;
}

-(NSString*)URLDecode
{
    return self.stringByRemovingPercentEncoding;
}

-(NSString*)URLEncode
{
    return [self stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet characterSetWithCharactersInString:@"!*'\"();:@&=+$,/?%#[]% "].invertedSet];
}


@end


@implementation NSData (Encode)

- (NSString*)base64Encode
{
    return [[NSString alloc] initWithData:[GTMBase64 encodeData:self] encoding:NSUTF8StringEncoding];
}

- (NSString*)base64Decode
{
    return [[NSString alloc] initWithData:[GTMBase64 decodeData:self] encoding:NSUTF8StringEncoding];
}

@end


