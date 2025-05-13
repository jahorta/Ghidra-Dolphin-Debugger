package dolphindebugger.GDBMessages;

public enum GDBMessageType {
    RESPONSE,       // Generic response to a command
    STOP_SIGNAL,    // e.g. S05 or T05 (target stopped)
    OUTPUT,         // e.g. Ooutput (console print)
    ERROR,          // e.g. E01 (error response)
    ASYNC,			// Anything command not expecting a response
    UNKNOWN         // Anything unrecognized
}