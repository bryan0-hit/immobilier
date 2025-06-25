export enum UserRole {
  GESTIONNAIRE = 'gestionnaire',
  BAILLEUR = 'bailleur',
  LOCATAIRE = 'locataire'
}

export enum PropertyStatus {
  DISPONIBLE = 'disponible',
  OCCUPE = 'occupe',
  EN_TRAVAUX = 'en_travaux',
  INDISPONIBLE = 'indisponible'
}

export enum PaymentStatus {
  PAYE = 'paye',
  EN_ATTENTE = 'en_attente',
  IMPAYE = 'impaye',
  PARTIEL = 'partiel'
}

export enum PaymentMethod {
  ESPECES = 'especes',
  CHEQUE = 'cheque',
  VIREMENT = 'virement',
  CARTE = 'carte',
  MOBILE_MONEY = 'mobile_money'
}

export enum RentalStatus {
  ACTIF = 'actif',
  EXPIRE = 'expire',
  RESILIE = 'resilie',
  SUSPENDU = 'suspendu'
}