package cia.northboat.encryption.crypto.pairing;

import java.util.List;

public interface SearchableEncryption {
    void setup();

    void keygen();

    default void enc(String w) {
        throw new UnsupportedOperationException("enc(String w) is not supported");
    }
    default void enc(List<String> W) {
        throw new UnsupportedOperationException("enc(List<String> W) is not supported");
    }

    default void trap(String q) {
        throw new UnsupportedOperationException("trap(String q) is not supported");
    }
    default void trap(List<String> Q) {
        throw new UnsupportedOperationException("trap(List<String> Q) is not supported");
    }

    boolean search();



    default void updateKey() {
        throw new UnsupportedOperationException("updateKey() is not supported");
    }
    default void reEnc() {
        throw new UnsupportedOperationException("updateEnc() is not supported");
    }

    default void constTrap(String q) {
        trap(q);
    }
    default void constTrap(List<String> Q) {
        trap(Q);
    }

    default boolean updateSearch() {
        return search();
    }

}
