package dolphindebugger.GDBMessages;

public class GDBMessage {
    private final String raw;
    private final GDBMessageType type;

    public GDBMessage(String raw, GDBMessageType type) {
        this.raw = raw;
        this.type = type;
    }

    public String getRaw() {
        return raw;
    }

    public GDBMessageType getType() {
        return type;
    }

    @Override
    public String toString() {
        return "[" + type + "] " + raw;
    }
    
    public byte[] toByteArray() {
        String hex = this.raw.startsWith("m") ? this.raw.substring(1) : this.raw; // optional RSP m prefix
        int len = hex.length();
        byte[] data = new byte[len / 2];

        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        }
        return data;
    }

    public static GDBMessage classify(String raw) {
        if (raw == null || raw.isEmpty())
            return new GDBMessage(raw, GDBMessageType.UNKNOWN);

        if (raw.matches("^S[0-9a-fA-F]{2}$") || raw.startsWith("T"))
            return new GDBMessage(raw, GDBMessageType.STOP_SIGNAL);
        if (raw.equalsIgnoreCase("OK")) return new GDBMessage(raw, GDBMessageType.RESPONSE);
        if (raw.startsWith("E"))
            return new GDBMessage(raw, GDBMessageType.ERROR);
        if (raw.startsWith("O"))
            return new GDBMessage(raw, GDBMessageType.OUTPUT);

        return new GDBMessage(raw, GDBMessageType.RESPONSE);
    }
}