package cia.northboat.encryption.crypto.tree.model;

import it.unisa.dia.gas.jpbc.Element;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;


@Data
@AllArgsConstructor
@Builder
public class Ciphertext {
    Element[] y;
    Element C;
    Element D;
    Element[] E;
}
