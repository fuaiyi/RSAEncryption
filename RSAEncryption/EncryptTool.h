//
//  EncryptTool.h
//  demo
//
//  Created by gaofu on 2017/3/20.
//  Copyright © 2017年 siruijk. All rights reserved.
//


#import <Foundation/Foundation.h>

typedef NS_ENUM(NSUInteger, KeyType)
{
    eKeyTypePublic,//公钥
    eKeyTypePrivate,//私钥
};



@interface EncryptTool : NSObject

+ (id)shareInstance;//单🌰
- (NSString *)encrypt:(NSString *)content type:(KeyType)type;//加密
- (NSString *)decrypt:(NSString *)content type:(KeyType)type;//解密

@end




@interface NSString (Encode)

- (NSData*) base64Encode;//base64编码
- (NSData*) base64Decode;//base64解码
- (NSString*) URLEncode;//URL编码
- (NSString*) URLDecode;//URL解码


@end



@interface NSData (Encode)

- (NSString*)base64Encode;//base64编码
- (NSString*)base64Decode;//base64解码

@end


