Imports System.Numerics

Public Class ElGamalPublicKey
    Sub New(p As BigInteger, g As BigInteger, y As BigInteger)
        Me.p = p
        Me.g = g
        Me.y = y
    End Sub

    Public Property p As BigInteger
    Public Property g As BigInteger
    Public Property y As BigInteger
End Class
