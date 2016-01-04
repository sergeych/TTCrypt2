package net.sergeych.ttcrypt;

/**
 * Created by sergeych on 04/01/16.
 */
public class Error extends Exception {
    public Error() { super(); }

    public Error(String reason) {
        super(reason);
    }
}
