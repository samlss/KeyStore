
package com.iigo.keystore;

import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.DividerItemDecoration;
import android.support.v7.widget.LinearLayoutManager;
import android.support.v7.widget.RecyclerView;
import android.text.TextUtils;
import android.util.Base64;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

public class MainActivity extends AppCompatActivity {
    private RecyclerView recyclerView;
    private Adapter adapter;
    private List<String> aliasList  = new ArrayList<>();
    private EditText editText;
    private TextView tvKey;
    private TextView tvCipher;

    private String plainText; //明文
    private String encryptData; //加密后字符串
    private String signedData; //签名后数据

    private String currentSelectedKeyAlias;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        initViews();
        updateKeys();

        //验证数据签名
//        String data = "1234";
//        byte[] sign = KeyStoreUtil.get().sign(data.getBytes(), "qq");
//        System.out.println("verify: "+KeyStoreUtil.get().verify(data.getBytes(), sign, "qq"));
    }

    private void updateKeys() {
        aliasList.clear();
        Enumeration<String> aliases = KeyStoreUtil.get().getAliases();
        if (aliases!= null){
            while (aliases.hasMoreElements()){
                aliasList.add(aliases.nextElement());
            }
        }
        adapter.notifyDataSetChanged();
    }

    private void initViews() {
        recyclerView = findViewById(R.id.recyclerview);
        recyclerView.setLayoutManager(new LinearLayoutManager(getApplicationContext()));
        recyclerView.addItemDecoration(new DividerItemDecoration(getBaseContext(), DividerItemDecoration.VERTICAL));
        adapter = new Adapter();
        adapter.setItemClickListener(itemClickListener);
        recyclerView.setAdapter(adapter);

        editText = findViewById(R.id.edit_text);
        tvKey = findViewById(R.id.tv_current);
        tvCipher = findViewById(R.id.tv_cipher);

        tvKey.setText(getString(R.string.current_key, ""));

        plainText = getString(R.string.plaintext);
    }

    @Override
    protected void onPause() {
        super.onPause();

        if (isFinishing()){
            aliasList.clear();
        }
    }

    public void onAddKey(View view){
        String alias = editText.getText().toString();
        if (!TextUtils.isEmpty(alias)){
            KeyStoreUtil.get().generateKey(getBaseContext(), alias);
            updateKeys();
        }
    }

    public void onDeleteKey(View view){
        deleteKey(editText.getText().toString());
    }

    private void deleteKey(String alias){
        if (!TextUtils.isEmpty(alias)){
            KeyStoreUtil.get().deleteKey(alias);
            updateKeys();
        }
    }

    private OnItemClickListener itemClickListener = new OnItemClickListener() {
        @Override
        public void onItemClick(View view, int position) {
            currentSelectedKeyAlias = aliasList.get(position);
            tvKey.setText(getString(R.string.current_key, currentSelectedKeyAlias));
        }

        @Override
        public boolean onItemLongClick(View view, int position) {
            deleteKey(aliasList.get(position));
            return true;
        }
    };

    public void doEncrypt(View view) {
        if (currentSelectedKeyAlias == null){
            Toast.makeText(getApplicationContext(), "请先选取alias", Toast.LENGTH_SHORT).show();
            return;
        }
        byte[] data = KeyStoreUtil.get().encrypt(plainText.getBytes(), currentSelectedKeyAlias);
        if (data != null){
            encryptData = Base64.encodeToString(data, Base64.DEFAULT);
            tvCipher.setText(getString(R.string.encrypt_content, encryptData));
        }
    }

    public void doDecrypt(View view) {
        if (currentSelectedKeyAlias == null){
            Toast.makeText(getApplicationContext(), "请先选取alias", Toast.LENGTH_SHORT).show();
            return;
        }
        if (TextUtils.isEmpty(encryptData)){
            Toast.makeText(getApplicationContext(), "请先进行加密操作", Toast.LENGTH_SHORT).show();
            return;
        }
        byte[] data = KeyStoreUtil.get().decrypt(Base64.decode(encryptData, Base64.DEFAULT), currentSelectedKeyAlias);
        if (data != null){
            tvCipher.setText(getString(R.string.decrypt_content, new String(data)));
        }
    }

    public void doSign(View view) {
        if (currentSelectedKeyAlias == null) {
            Toast.makeText(getApplicationContext(), "请先选取alias", Toast.LENGTH_SHORT).show();
            return;
        }
        // do sha-256
        byte[] shadata = KeyStoreUtil.get().encryptSHA(plainText.getBytes(), KeyStoreUtil.SHA_ALG);
        byte[] data = KeyStoreUtil.get().sign(shadata, currentSelectedKeyAlias);
//        byte[] data = KeyStoreUtil.get().sign(plainText.getBytes(), currentSelectedKeyAlias);
        if (data != null) {
            signedData = Base64.encodeToString(data, Base64.DEFAULT);
            tvCipher.setText(getString(R.string.verify_sign, signedData));
        }
    }

    public void doVerify(View view) {
        if (currentSelectedKeyAlias == null) {
            Toast.makeText(getApplicationContext(), "请先选取alias", Toast.LENGTH_SHORT).show();
            return;
        }
        if (TextUtils.isEmpty(signedData)){
            Toast.makeText(getApplicationContext(), "请先进行签名操作", Toast.LENGTH_SHORT).show();
            return;
        }

        byte[] shadata = KeyStoreUtil.get().encryptSHA(plainText.getBytes(), KeyStoreUtil.SHA_ALG);
        boolean verify = KeyStoreUtil.get().verify(shadata, Base64.decode(signedData, Base64.DEFAULT), currentSelectedKeyAlias);
//        boolean verify = KeyStoreUtil.get().verify(plainText.getBytes(),signedData.getBytes(),currentSelectedKeyAlias);

        tvCipher.setText(getString(R.string.verify_content, (verify) ? "match" : "not match"));

    }

    private class  ViewHolder extends RecyclerView.ViewHolder{
        TextView textView;
        public ViewHolder(View itemView) {
            super(itemView);

            textView = itemView.findViewById(R.id.tv_name);
        }
    }

    private class Adapter extends RecyclerView.Adapter<ViewHolder> {
        private OnItemClickListener itemClickListener;
        @NonNull
        @Override
        public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            View view = getLayoutInflater().inflate(R.layout.layout_item, parent, false);
            return new ViewHolder(view);
        }

        @Override
        public void onBindViewHolder(@NonNull ViewHolder holder, final int position) {
            holder.textView.setText(aliasList.get(position));

            holder.itemView.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    if (itemClickListener != null){
                        itemClickListener.onItemClick(v, position);
                    }
                }
            });

            holder.itemView.setOnLongClickListener(new View.OnLongClickListener() {
                @Override
                public boolean onLongClick(View v) {
                    if (itemClickListener != null){
                        return itemClickListener.onItemLongClick(v, position);
                    }
                    return false;
                }
            });
        }

        @Override
        public int getItemCount() {
            return aliasList.size();
        }

        public void setItemClickListener(OnItemClickListener itemClickListener){
            this.itemClickListener = itemClickListener;
        }

    }

    public interface OnItemClickListener{
        void onItemClick(View view, int position);

        boolean onItemLongClick(View view, int position);
    }
}
