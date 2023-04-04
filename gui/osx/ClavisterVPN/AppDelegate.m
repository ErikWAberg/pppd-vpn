#import "AppDelegate.h"
#import "ViewController.h"
#import "vpn.h"

@interface AppDelegate ()


@end


@implementation AppDelegate



@synthesize menubarIconMenu;
@synthesize menubarIconMenuStats;
@synthesize menubarIconMenuConnect;
@synthesize menubarIconMenuDisconnect;
@synthesize menubarIconMenuClose;
@synthesize menubarIconStatusItem;

static char configFilePath[200] = {0};

static int previousVpnState = -1;

static id this;

void vpn_state_callback(int newState) {
    NSLog(@"Received new VPN State: %d", newState);
    dispatch_async(dispatch_get_main_queue(), ^{
        [this handleNewVpnState:newState];
        //this runs on the main thread.
    });
}

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
    // Insert code here to initialize your application
    if(getuid() != 0 && geteuid() != 0) {
        NSAlert *alert = [[NSAlert alloc] init];
        [alert setMessageText:@"Requires root"];
        [alert setInformativeText:@"Application must currently be run as root, see user instructions."];
        [alert addButtonWithTitle:@"Ok"];
        if([alert runModal] == NSAlertFirstButtonReturn) {
            [self terminateApp];
        }
    }
    
    self.window = [NSApplication sharedApplication].keyWindow;
    this = self;
    memset(configFilePath, 0, strlen(configFilePath));
    vpn_set_state_callback(vpn_state_callback);
    [self allocMenubar];
    [self handleNewVpnState:0];
    [self readTextStorage];
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)sender {
    return NO;
}


- (void)applicationWillTerminate:(NSNotification *)aNotification {
    // Insert code here to tear down your application
    NSLog(@"Application will terminate");
    [self disconnect];
    [self terminateApp];
    
}

- (BOOL)applicationShouldHandleReopen:(NSApplication *)theApplication hasVisibleWindows:(BOOL)visibleWindows
{
    NSLog(@"Should handle reopen");
   
    if ( visibleWindows ) {
        NSLog(@"Visible windows");
        [self.window orderFront:self];
    }
    else {
        NSLog(@"No visible windows");
       // self.viewController = [ViewController alloc];
       // [self.viewController loadView];
    }
    
    return YES;
}


- (void)windowWillClose:(NSNotification *)notification {
     NSLog(@"Delegate: Main windowWillClose");
}


- (IBAction)openStatisticsWindow:(id)sender {
    [self openStatistics];
}

- (void) openStatistics {
    NSLog(@"UI: Loading statistics.");
   
    self.statisticsWindowController = [[StatisticsWindowController alloc] initWithWindowNibName:@"StatisticsWindowController"];

    [self.statisticsWindowController showWindow:self];
    [self.statisticsWindowController windowOpened];
}

- (void)sayHello:(ViewController*) viewController {
    self.viewController = viewController;
}


- (void) allocMenubar {
    
    menubarIconMenu = [NSMenu alloc];
    [menubarIconMenu setAutoenablesItems:NO];
    menubarIconMenuStats = [NSMenuItem alloc];
    [menubarIconMenuStats setTitle:@"Statistics"];
    [menubarIconMenuStats setAction:@selector(openStatistics)];
    [menubarIconMenu addItem:menubarIconMenuStats];
    
    menubarIconMenuConnect = [NSMenuItem alloc];
    [menubarIconMenuConnect setTitle:@"Connect"];
    [menubarIconMenuConnect setAction:@selector(connect)];
    [menubarIconMenu addItem:menubarIconMenuConnect];
    
    menubarIconMenuDisconnect = [NSMenuItem alloc];
    [menubarIconMenuDisconnect setTitle:@"Disconnect"];
    [menubarIconMenuDisconnect setAction:@selector(disconnect)];
    [menubarIconMenu addItem:menubarIconMenuDisconnect];
    
    [menubarIconMenuDisconnect setEnabled:NO];
    
    menubarIconMenuClose = [NSMenuItem alloc];
    [menubarIconMenuClose setTitle:@"Quit"];
    [menubarIconMenuClose setAction:@selector(terminateApp)];
    [menubarIconMenu addItem:menubarIconMenuClose];
    
    
    menubarIconStatusItem = [[NSStatusBar systemStatusBar] statusItemWithLength:NSVariableStatusItemLength];
    [menubarIconStatusItem setToolTip:@"pppd-VPN"];
    [menubarIconStatusItem setHighlightMode:YES];
    [menubarIconStatusItem setMenu:menubarIconMenu];
    
}

- (void) connect {
    [self.viewController handleConnect:self];
}

- (void) disconnect {
    [self.viewController handleCancel:self];
    
    vpn_terminate();    
    
}

- (void) terminateApp {
    [NSApp performSelector:@selector(terminate:) withObject:nil afterDelay:0.0];
}

- (void) handleNewVpnState:(int)state {
    
    NSImage* menuImage = nil;

    if(state != previousVpnState) {
        previousVpnState = state;
        [self.viewController handleNewVpnState:state];
        
        NSLog(@"AppDelegate: Updating menubar icon");
        switch(state) {
            case VPN_DISCONNECTED:
                menuImage = [NSImage imageNamed:@"MenubarDisconnected"];
                [menubarIconMenuDisconnect setEnabled:NO];
                [menubarIconMenuConnect setEnabled:YES];
                
                
                if(self.statisticsWindowController)
                    [self.statisticsWindowController handleDisconnect];
                
                break;
                
            case VPN_CONNECTED:
                menuImage = [NSImage imageNamed:@"MenubarConnected"];
                [menubarIconMenuDisconnect setEnabled:YES];
                [menubarIconMenuConnect setEnabled:NO];
                
                if(self.statisticsWindowController)
                    [self.statisticsWindowController loadAddressInfo];
                
                break;
                
            case VPN_CONNECTING:
                menuImage = [NSImage imageNamed:@"MenubarConnecting"];
                break;
                default:
                menuImage = [NSImage imageNamed:@"MenubarInit"];
                break;
        }
        [menubarIconStatusItem setImage:menuImage];
        
    }
}



- (void) readTextStorage {
    //get the documents directory:
    NSArray *paths = NSSearchPathForDirectoriesInDomains
    (NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *documentsDirectory = [paths objectAtIndex:0];
    
    //make a file name to write the data to using the documents directory:
    NSString *fileName = [NSString stringWithFormat:@"%@/pppd-VPN",
                          documentsDirectory];
    NSString *content = [NSString stringWithContentsOfFile:fileName encoding:NSStringEncodingConversionAllowLossy error:nil];
    if ([content hasSuffix:@".csslv"]){
        NSLog(@"Found previous config file %@", content);
        const char* configPath = [content UTF8String];
        memset(configFilePath, 0, strlen(configFilePath));
        strncpy(configFilePath, configPath, strlen(configPath));
        NSLog(@"File path: %s", configFilePath );

        if(self.viewController) {
            [self.viewController openConfigurationFile:configFilePath];
        }
    }
    
}

- (void) writeToTextFile:(NSString*)content {
    //get the documents directory:

    NSArray *paths = NSSearchPathForDirectoriesInDomains
    (NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *documentsDirectory = [paths objectAtIndex:0];
    
    //make a file name to write the data to using the documents directory:
    NSString *fileName = [NSString stringWithFormat:@"%@/pppd-VPN",
                          documentsDirectory];
        NSLog(@"Writing file %@", fileName);
    //create content - four lines of text

    
    //save content to the documents directory
    [content writeToFile:fileName
              atomically:NO
                encoding:NSStringEncodingConversionAllowLossy
                   error:nil];
    
}


- (IBAction)openConfigurationFile:(id)sender {
    
    NSLog(@"Open configuration file");
    
    NSOpenPanel* openPanel = [NSOpenPanel openPanel];
    
    openPanel.title = @"Choose an .csslv file.";
    openPanel.showsResizeIndicator = YES;
    openPanel.showsHiddenFiles = NO;
    openPanel.canChooseDirectories = NO;
    openPanel.canCreateDirectories = NO;
    openPanel.allowsMultipleSelection = NO;
    openPanel.allowedFileTypes = @[@"csslv"];

    NSInteger result =[openPanel runModal];

    static const char* configPath;
    if(result == NSModalResponseOK)
    {
        NSURL* configFileUrl = [openPanel URL];
        NSLog(@"Configuration file path: %@",configFileUrl );
        if([configFileUrl isFileURL]) {
            NSString* path = [configFileUrl path];
            configPath = [path UTF8String];
            memset(configFilePath, 0, strlen(configFilePath));
            strncpy(configFilePath, configPath, strlen(configPath));
            NSLog(@"File path: %s", configFilePath );
            [self writeToTextFile:path];
            if(self.viewController) {
                [self.viewController openConfigurationFile:configFilePath];
            }

        }
     
    }
}


@end
