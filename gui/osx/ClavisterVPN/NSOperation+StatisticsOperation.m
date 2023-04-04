#import "NSOperation+StatisticsOperation.h"

//C-Includes
#import "vpn.h"


@implementation StatisticsOperation : NSOperation


- (void)main
{
    double kB_rate_in = 0;
    double kB_rate_out = 0;
    uint64_t bytes_in = 0;
    uint64_t bytes_out = 0;
    
    uint64_t prev_bytes_in = 0;
    uint64_t prev_bytes_out = 0;

    double MB = 1000 * 1000.0;
    double kB = 1000.0;
    
    float updateRate = 1.0; //seconds
  
    
    while(![self isCancelled]) {

        if(vpn_get_state() == VPN_CONNECTED) {

            prev_bytes_in = bytes_in;
            prev_bytes_out = bytes_out;
            
            NSMutableDictionary *dict = [[NSMutableDictionary alloc]initWithCapacity:4];
            
            bytes_in = vpn_get_bytes_received();
            bytes_out = vpn_get_bytes_sent();
            
            kB_rate_in = (bytes_in - prev_bytes_in) / (updateRate * kB);
            kB_rate_out = (bytes_out - prev_bytes_out) / (updateRate * kB);
            
            
            NSString *sBytes_in = [NSString stringWithFormat:@"%.2f MB", bytes_in / MB];
            NSString *sBytes_out = [NSString stringWithFormat:@"%.2f MB", bytes_out / MB];
            NSString *sRate_in;
            NSString *sRate_out;
            
            if(kB_rate_in < kB) {
                sRate_in = [NSString stringWithFormat:@"%.1f kB/s", kB_rate_in];
            } else {
                sRate_in = [NSString stringWithFormat:@"%.1f MB/s", kB_rate_in];
            }
            
            if(kB_rate_out < kB) {
                sRate_out = [NSString stringWithFormat:@"%.1f kB/s", kB_rate_out];
            } else {
                sRate_out = [NSString stringWithFormat:@"%.1f MB/s", kB_rate_out / kB];
            }
            
            [dict setObject: sBytes_in forKey:@"bytes_in"];
            [dict setObject: sBytes_out forKey:@"bytes_out"];
            [dict setObject: sRate_in forKey:@"rate_in"];
            [dict setObject: sRate_out forKey:@"rate_out"];
            
            
            //NSLog(@"in: %llul, out: %llul, in_rate: %f, out_rate: %f", bytes_in, bytes_out, kB_rate_in, kB_rate_out);
           // NSLog(@"Statistics thread:\nBytes in: %@\nBytes out: %@\nRate in: %@\nRate out: %@", sBytes_in, sBytes_out,sRate_in, sRate_out);
            
            [self performSelectorOnMainThread:@selector(sendNotificationOnMainThread:)
                                   withObject:[NSNotification notificationWithName:@"StatisticsNotification"
                                                                            object:self
                                                                          userInfo:dict]
                                waitUntilDone:NO];
        
        }
        
        
        [NSThread sleepForTimeInterval:updateRate];
    }
    
    NSLog(@"Statistics cancelled");
    return;
}

- (void)sendNotificationOnMainThread:(NSNotification *)note
{
    NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
    [nc postNotification:note];
}

@end
