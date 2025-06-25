import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, ManyToOne, OneToMany, JoinColumn } from 'typeorm';
import { Bien } from 'src/bien/entities/bien.entity';
import { Utilisateur } from 'src/users/entities/user.entity';
import { Paiement } from 'src/paiement/entities/paiement.entity';
import { RentalStatus } from 'src/enums/enums';

@Entity('locations')
export class Location {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  bienId: string;

  @Column({ type: 'uuid' })
  pieceId: string; // Référence à l'ID de la pièce dans le tableau pieces du bien

  @Column({ type: 'uuid' })
  locataireId: string;

  @Column({ type: 'date' })
  debut: Date;

  @Column({ type: 'date', nullable: true })
  fin: Date;

  @Column({ type: 'decimal', precision: 10, scale: 2 })
  loyerMensuel: number;

  @Column({ type: 'decimal', precision: 10, scale: 2, default: 0 })
  chargesMensuelles: number;

  @Column({ type: 'decimal', precision: 10, scale: 2, nullable: true })
  caution: number;

  @Column({ type: 'enum', enum: RentalStatus, default: RentalStatus.ACTIF })
  statut: RentalStatus;

  @Column({ type: 'varchar', length: 255, nullable: true })
  cheminContrat: string;

  @Column({ type: 'varchar', length: 255, nullable: true })
  nomFichierContrat: string;

  @CreateDateColumn()
  creeLe: Date;

  @UpdateDateColumn()
  misAJourLe: Date;

  @ManyToOne(() => Bien, bien => bien.locations)
  @JoinColumn({ name: 'bienId' })
  bien: Bien;

  @ManyToOne(() => Utilisateur, utilisateur => utilisateur.locations)
  @JoinColumn({ name: 'locataireId' })
  locataire: Utilisateur;

  @OneToMany(() => Paiement, paiement => paiement.location)
  paiements: Paiement[];
}