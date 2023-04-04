#import <Foundation/Foundation.h>

@interface StatisticsOperation : NSOperation

- (void)sendNotificationOnMainThread:(NSNotification *)note;

@end
